import pytest
import time
import logging
import json
import sys
import traceback
from tests.ptf_runner import ptf_runner
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.vxlan_ecmp_utils import Ecmp_Utils
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory  # noqa: F401

# Constants
VNET_NAME = "Vnet1"
VNET2_NAME = "Vnet2"
TUNNEL_NAME = "tunnel_v4"
VNI = 1000
VNET2_VNI = 2000
# Override VNI used by the per-route mac_address / vni test. Different from the
# VNET vni so we can confirm the route-level vni overrides the VNET vni when
# building the VXLAN encap header.
ROUTE_OVERRIDE_VNI = 5001
PREFIX = "150.0.3.1/24"
BUCKET_SIZE = 512
# Larger bucket count used by the scale tests. The hardware caps the actual
# number of programmed buckets at MAX_HW_BUCKET_SIZE (511), but the route
# entry can still be configured with a larger logical bucket size and the
# orchagent / SAI layer is expected to clamp it.
BUCKET_SIZE_LARGE = 2048
# Hardware-supported maximum number of FG ECMP buckets. Adding endpoints
# beyond this should be rejected by the DUT (the new endpoint never
# receives traffic).
MAX_HW_BUCKET_SIZE = 511
NUM_INITIAL_ENDPOINTS = 10
# Endpoint counts used by the scale tests.
LARGE_ENDPOINT_COUNT = 128
MAX_ENDPOINT_COUNT = MAX_HW_BUCKET_SIZE       # 511 -- still fits in HW
OVERFLOW_ENDPOINT_COUNT = MAX_HW_BUCKET_SIZE + 1  # 512 -- one too many
ENDPOINT_BASE_IP = "100.0.1."
VNET2_ENDPOINT_BASE_IP = "100.0.2."
VNET2_DUT_IP = "202.0.1.1"
VNET2_PTF_IP = "202.0.1.101"
NUM_FLOWS = 1000
CONFIG_DB_PATH = '/etc/sonic/config_db.json'
PERSIST_MAP_FILE = '/tmp/vxlan_tunnel_fg_ecmp_persist_map.json'
PTF_PARAMS_FILE = '/tmp/vxlan_tunnel_fg_ecmp_ptf_params.json'
PTF_LOG_FILE = '/tmp/vxlan_tunnel_fg_ecmp_test.log'

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.device_type('physical'),
    pytest.mark.asic('cisco-8000')
]

logger = logging.getLogger(__name__)
ecmp_utils = Ecmp_Utils()


def generate_endpoint_list(base_ip=ENDPOINT_BASE_IP, count=NUM_INITIAL_ENDPOINTS):
    return [f"{base_ip}{i}" for i in range(count)]


def generate_large_endpoint_list(count, base_prefix="100.10"):
    """
    Generate `count` distinct IPv4 endpoints by walking the third and fourth
    octets of base_prefix.X.Y. Used by the scale tests that need more
    endpoints than fit in a single /24.
    """
    endpoints = []
    third = 0
    fourth = 1   # avoid .0
    while len(endpoints) < count:
        endpoints.append(f"{base_prefix}.{third}.{fourth}")
        fourth += 1
        if fourth > 254:
            fourth = 1
            third += 1
            assert third <= 255, f"Cannot generate {count} endpoints in {base_prefix}.0.0/16"
    return endpoints


def get_loopback_ip(cfg_facts):
    for key in cfg_facts.get("LOOPBACK_INTERFACE", {}):
        if key.startswith("Loopback0|") and "." in key:
            return key.split("|")[1].split("/")[0]
    pytest.fail("Cannot find IPv4 Loopback0 address in LOOPBACK_INTERFACE")


def apply_chunk(duthost, payload, name):
    content = json.dumps(payload, indent=2)
    dest = f"/tmp/{name}.json"
    duthost.copy(content=content, dest=dest)
    duthost.shell(f"sonic-cfggen -j {dest} --write-to-db")


def get_available_vlan_id_and_ports(cfg_facts, num_ports_needed, exclude_ports=None):
    """
    Return (vlan_id, available_ports) from the first VLAN that has
    enough admin up ports. Ports in exclude_ports are skipped.
    """
    port_status = cfg_facts["PORT"]
    pytest_require("VLAN_MEMBER" in cfg_facts, "Can't get vlan member")
    excluded = set(exclude_ports or [])

    for vlan_name, members in list(cfg_facts["VLAN_MEMBER"].items()):
        if len(members) < num_ports_needed:
            continue

        possible_ports = []
        for vlan_member in members:
            if vlan_member in excluded:
                continue
            if port_status[vlan_member].get("admin_status", "down") != "up":
                continue
            possible_ports.append(vlan_member)
            if len(possible_ports) == num_ports_needed:
                vlan_id = int(''.join([c for c in vlan_name if c.isdigit()]))
                logger.debug(f"Vlan {vlan_id} has available ports: {possible_ports}")
                return vlan_id, possible_ports

    pytest.fail(f"Could not find a VLAN with {num_ports_needed} up port(s) (excluding {excluded})")


def set_route_tunnel_regular(duthost, endpoints):
    """Program a regular ECMP route (no consistent hashing)."""
    logger.info(f"Programming regular ECMP route {PREFIX} -> {','.join(endpoints)}")
    vni_str = ",".join([str(VNI)] * len(endpoints))
    apply_chunk(
        duthost,
        {"VNET_ROUTE_TUNNEL": {
            f"{VNET_NAME}|{PREFIX}": {
                "endpoint": ",".join(endpoints),
                "vni": vni_str,
            }
        }},
        "route_tunnel",
    )
    # sonic-cfggen merges fields, so explicitly remove the FG ECMP field
    # in case it was set previously
    duthost.shell(
        f"sonic-db-cli CONFIG_DB hdel "
        f"'VNET_ROUTE_TUNNEL|{VNET_NAME}|{PREFIX}' "
        f"consistent_hashing_buckets"
    )
    time.sleep(3)


def set_route_tunnel(duthost, endpoints, bucket_size=BUCKET_SIZE):
    logger.info(
        f"Programming route {PREFIX} -> {len(endpoints)} endpoints, "
        f"buckets={bucket_size}"
    )
    vni_str = ",".join([str(VNI)] * len(endpoints))
    apply_chunk(
        duthost,
        {"VNET_ROUTE_TUNNEL": {
            f"{VNET_NAME}|{PREFIX}": {
                "endpoint": ",".join(endpoints),
                "vni": vni_str,
                "consistent_hashing_buckets": str(bucket_size),
            }
        }},
        "route_tunnel",
    )
    time.sleep(3)


def set_route_tunnel_with_mac_vni(duthost, endpoints, mac_list, vni):
    """
    Program the FG ECMP route with a per-endpoint mac_address list and an
    explicit override vni (applied to every endpoint). The mac_list and
    endpoints lists must have the same length. Removes any stale fields so
    sonic-cfggen merges produce the exact intended state.
    """
    assert len(mac_list) == len(endpoints), (
        f"mac_list length {len(mac_list)} must equal endpoints length {len(endpoints)}"
    )
    logger.info(
        f"Programming FG ECMP route {PREFIX} with vni={vni}, "
        f"endpoints={endpoints}, mac_list={mac_list}"
    )
    vni_str = ",".join([str(vni)] * len(endpoints))
    mac_str = ",".join(mac_list)
    apply_chunk(
        duthost,
        {"VNET_ROUTE_TUNNEL": {
            f"{VNET_NAME}|{PREFIX}": {
                "endpoint": ",".join(endpoints),
                "vni": vni_str,
                "mac_address": mac_str,
                "consistent_hashing_buckets": str(BUCKET_SIZE),
            }
        }},
        "route_tunnel",
    )
    time.sleep(3)


def cleanup(duthost, ptfhost):
    duthost.shell(f"mv {CONFIG_DB_PATH}.bak {CONFIG_DB_PATH}")
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
    for f in [PERSIST_MAP_FILE, PTF_PARAMS_FILE, PTF_LOG_FILE]:
        ptfhost.shell(f"rm -f {f}")


def get_t1_facing_ptf_ports(duthost, tbinfo):
    """Return PTF port indices of DUT interfaces facing T1 BGP neighbors.

    Used to validate that VXLAN-encapped packets egress only on uplinks.
    """
    minigraph_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ptf_indices = minigraph_facts["minigraph_ptf_indices"]
    neighbors = minigraph_facts["minigraph_neighbors"]
    t1_ports = sorted({
        ptf_indices[intf]
        for intf, info in neighbors.items()
        if info.get("name", "").endswith("T1") and intf in ptf_indices
    })
    logger.info(f"T1-facing PTF port indices: {t1_ports}")
    return t1_ports


def vxlan_setup_one_vnet(duthost, ptfhost, tbinfo, cfg_facts,
                         config_facts, dut_indx, vxlan_port):
    vlan_id, ports = get_available_vlan_id_and_ports(config_facts, 1)
    pytest_assert(ports, "No available VLAN ports for VNET setup")

    port_indexes = config_facts["port_index_map"]
    host_interfaces = tbinfo["topo"]["ptf_map"][str(dut_indx)]
    ptf_ports_available_in_topo = {host_interfaces[k]: f"eth{k}" for k in host_interfaces}
    logger.info(f"PTF port map: {ptf_ports_available_in_topo}")

    ecmp_utils.Constants["KEEP_TEMP_FILES"] = False
    ecmp_utils.Constants["DEBUG"] = True

    ingress_if = ports[0]
    logger.info(f"Selected ingress interface: {ingress_if} from VLAN {vlan_id}")

    # Remove port from its VLAN so we can bind it directly to the VNET interface
    duthost.shell(f"config vlan member del {vlan_id} {ingress_if} || true")

    dut_vtep = get_loopback_ip(cfg_facts)
    logger.info(f"Creating VXLAN tunnel {TUNNEL_NAME} with source {dut_vtep}")

    apply_chunk(duthost, {"VXLAN_TUNNEL": {TUNNEL_NAME: {"src_ip": dut_vtep}}}, "vxlan_tunnel")
    apply_chunk(duthost, {"VNET": {VNET_NAME: {"vni": str(VNI), "vxlan_tunnel": TUNNEL_NAME}}}, "vnet")

    ptf_port_index = port_indexes[ingress_if]
    ptf_port_name = ptf_ports_available_in_topo[ptf_port_index]

    dut_ip = "201.0.1.1"
    apply_chunk(
        duthost,
        {"INTERFACE": {ingress_if: {"vnet_name": VNET_NAME}, f"{ingress_if}|{dut_ip}/24": {}}},
        "intf_bind",
    )

    ptf_ip = "201.0.1.101"
    ptfhost.shell(f"ip link set {ptf_port_name} up")

    ecmp_utils.configure_vxlan_switch(duthost, vxlan_port=vxlan_port,
                                      dutmac=duthost.facts["router_mac"])

    initial_endpoints = generate_endpoint_list()
    set_route_tunnel(duthost, initial_endpoints)
    time.sleep(3)

    expected_egress_ports = get_t1_facing_ptf_ports(duthost, tbinfo)

    return {
        "dut_vtep": dut_vtep,
        "ptf_src_ip": ptf_ip,
        "dst_ip": PREFIX.split("/")[0],
        "ptf_ingress_port": ptf_port_index,
        "router_mac": duthost.facts["router_mac"],
        "vxlan_port": vxlan_port,
        "ptf_port_name": ptf_port_name,
        "ingress_if": ingress_if,
        "expected_egress_ports": expected_egress_ports,
    }


def setup_second_vnet(duthost, ptfhost, tbinfo, config_facts, dut_indx, first_ingress_if):
    vlan_id, ports = get_available_vlan_id_and_ports(
        config_facts, 1, exclude_ports=[first_ingress_if]
    )
    pytest_assert(ports, "No available VLAN ports for Vnet2 setup")

    port_indexes = config_facts["port_index_map"]
    host_interfaces = tbinfo["topo"]["ptf_map"][str(dut_indx)]
    ptf_ports_available_in_topo = {host_interfaces[k]: f"eth{k}" for k in host_interfaces}

    ingress_if2 = ports[0]
    logger.info(f"Selected Vnet2 ingress interface: {ingress_if2} from VLAN {vlan_id}")

    duthost.shell(f"config vlan member del {vlan_id} {ingress_if2} || true")

    apply_chunk(duthost, {"VNET": {VNET2_NAME: {"vni": str(VNET2_VNI), "vxlan_tunnel": TUNNEL_NAME}}}, "vnet2")

    apply_chunk(
        duthost,
        {"INTERFACE": {ingress_if2: {"vnet_name": VNET2_NAME}, f"{ingress_if2}|{VNET2_DUT_IP}/24": {}}},
        "intf_bind_vnet2",
    )

    ptf_port_index2 = port_indexes[ingress_if2]
    ptf_port_name2 = ptf_ports_available_in_topo[ptf_port_index2]

    ptfhost.shell(f"ip link set {ptf_port_name2} up")

    vnet2_endpoints = generate_endpoint_list(VNET2_ENDPOINT_BASE_IP, NUM_INITIAL_ENDPOINTS)
    set_route_tunnel(duthost, vnet2_endpoints, vnet_name=VNET2_NAME, vni=VNET2_VNI)

    return {
        "ptf_src_ip": VNET2_PTF_IP,
        "ptf_ingress_port": ptf_port_index2,
        "ptf_port_name": ptf_port_name2,
    }


@pytest.fixture(scope="module", autouse=True)
def common_setup_teardown(
    duthosts,
    rand_one_dut_hostname,
    ptfhost,
    tbinfo,
    request,
):
    """
    Module-level setup:
    - Configures 1 VNET, 1 VXLAN tunnel, and 1 VNET route with fine-grained ECMP
    """
    duthost = duthosts[rand_one_dut_hostname]
    duthost.shell(f"cp {CONFIG_DB_PATH} {CONFIG_DB_PATH}.bak")

    setup_params = None
    try:
        cfg_facts = json.loads(duthost.shell("sonic-cfggen -d --print-data")["stdout"])
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
        duts_map = tbinfo["duts_map"]
        dut_indx = duts_map[duthost.hostname]
        vxlan_port = request.config.option.vxlan_port

        setup_params = vxlan_setup_one_vnet(
            duthost, ptfhost, tbinfo, cfg_facts, config_facts, dut_indx, vxlan_port
        )

        vnet2_params = setup_second_vnet(
            duthost, ptfhost, tbinfo, config_facts, dut_indx,
            first_ingress_if=setup_params["ingress_if"],
        )
        setup_params["vnet2"] = vnet2_params

        yield setup_params, duthost, ptfhost

    except Exception as e:
        logger.error("Exception raised in setup: {}".format(repr(e)))
        logger.error(json.dumps(traceback.format_exception(*sys.exc_info()), indent=2))
        pytest.fail("Vnet testing setup failed")

    finally:
        cleanup(duthost, ptfhost)


def run_regular_ecmp_ptf_test(ptfhost, endpoints, params, num_packets):
    """Run the regular ECMP PTF test (all endpoints hit, no loss)."""
    logger.info(f"Regular ECMP PTF test: {len(endpoints)} endpoints, {num_packets} packets")
    endpoints_file = "/tmp/ptf_endpoints.json"
    ptfhost.copy(content=json.dumps(endpoints), dest=endpoints_file)

    ptf_params = params.copy()
    ptf_params.update({
        "endpoints_file": endpoints_file,
        "num_packets": num_packets,
    })
    params_path = "/tmp/ptf_regular_ecmp_params.json"
    ptfhost.copy(content=json.dumps(ptf_params), dest=params_path)

    ptf_runner(
        ptfhost,
        "ptftests",
        "vxlan_ecmp_ptftest.VxlanEcmpTest",
        platform_dir="ptftests",
        params={"params_file": params_path},
        log_file="/tmp/vxlan_regular_ecmp_test.log",
        qlen=1000,
        is_python3=True,
    )


def run_vxlan_ptf_test(ptfhost, endpoints, params, test_case, num_packets,
                       check_distribution=True, require_all_endpoints_hit=True,
                       **kwargs):
    """
    `check_distribution` controls whether expected flows-per-endpoint values
    are sent to PTF (and the deviation check runs). Disable it for the scale
    tests where the flow:endpoint ratio is too low for meaningful deviation.

    `require_all_endpoints_hit` controls the strict assertion that every
    configured endpoint received at least one flow. With many endpoints and
    relatively few flows it is statistically expected that some endpoints
    receive zero flows, so disable it for the scale tests.
    """
    logger.info(
        f"PTF test: test_case={test_case}, endpoints={len(endpoints)}, "
        f"flows={num_packets}, check_distribution={check_distribution}, "
        f"require_all_endpoints_hit={require_all_endpoints_hit}"
    )

    if check_distribution:
        flows_per_nh = num_packets / len(endpoints)
        exp_flow_count = {ep: flows_per_nh for ep in endpoints}
    else:
        exp_flow_count = {}

    ptf_params = params.copy()

    ptf_params.update({
        "endpoints": endpoints,
        "test_case": test_case,
        "num_packets": num_packets,
        "exp_flow_count": exp_flow_count,
        "require_all_endpoints_hit": require_all_endpoints_hit,
        "persist_map": PERSIST_MAP_FILE,
    })
    ptf_params.update(kwargs)

    ptfhost.copy(content=json.dumps(ptf_params), dest=PTF_PARAMS_FILE)

    ptf_runner(
        ptfhost,
        "ptftests",
        "vxlan_tunnel_fg_ecmp_test.VxlanTunnelFgEcmpTest",
        platform_dir="ptftests",
        params={"params_file": PTF_PARAMS_FILE},
        log_file=PTF_LOG_FILE,
        qlen=1000,
        is_python3=True,
    )


def test_vxlan_fg_ecmp(ptfhost, common_setup_teardown):
    logger.info("Running test_vxlan_fg_ecmp")
    setup, duthost, _ = common_setup_teardown

    endpoints = generate_endpoint_list()

    run_vxlan_ptf_test(ptfhost, endpoints, setup, "create_flows", num_packets=NUM_FLOWS)

    run_vxlan_ptf_test(ptfhost, endpoints, setup, "verify_consistent_hash", num_packets=NUM_FLOWS)

    # Withdraw one endpoint; only its ~100 flows should redistribute
    withdrawn_endpoint = endpoints[-1]
    remaining_endpoints = endpoints[:-1]
    set_route_tunnel(duthost, remaining_endpoints)
    run_vxlan_ptf_test(
        ptfhost, remaining_endpoints, setup, "withdraw_endpoint",
        num_packets=NUM_FLOWS, withdraw_endpoint=withdrawn_endpoint,
    )

    new_endpoint = f"{ENDPOINT_BASE_IP}{NUM_INITIAL_ENDPOINTS}"  # 100.0.1.10
    readded_endpoints = remaining_endpoints + [new_endpoint]
    set_route_tunnel(duthost, readded_endpoints)
    run_vxlan_ptf_test(
        ptfhost, readded_endpoints, setup, "add_endpoint",
        num_packets=NUM_FLOWS, add_endpoint=new_endpoint,
    )

    # Simultaneously remove 2 endpoints and add 2 new ones. Total endpoint
    # count is unchanged so the bucket layout stays the same; flows on
    # unchanged endpoints must remain on the same endpoint, and only flows
    # whose previous endpoint was withdrawn may redistribute.
    withdrawn_endpoints = readded_endpoints[:2]
    kept_endpoints = readded_endpoints[2:]
    added_endpoints = [
        f"{ENDPOINT_BASE_IP}{NUM_INITIAL_ENDPOINTS + 1}",  # 100.0.1.11
        f"{ENDPOINT_BASE_IP}{NUM_INITIAL_ENDPOINTS + 2}",  # 100.0.1.12
    ]
    swapped_endpoints = kept_endpoints + added_endpoints
    set_route_tunnel(duthost, swapped_endpoints)
    run_vxlan_ptf_test(
        ptfhost, swapped_endpoints, setup, "swap_endpoints",
        num_packets=NUM_FLOWS,
        withdrawn_endpoints=withdrawn_endpoints,
        added_endpoints=added_endpoints,
    )

    vnet2 = setup["vnet2"]
    vnet2_endpoints = generate_endpoint_list(VNET2_ENDPOINT_BASE_IP, NUM_INITIAL_ENDPOINTS)
    run_vxlan_ptf_test(
        ptfhost,
        endpoints,  # Vnet1 endpoints
        setup,
        "conflicting_dest_prefix",
        num_packets=NUM_FLOWS,
        vnet2_endpoints=vnet2_endpoints,
        ptf_ingress_port_vnet2=vnet2["ptf_ingress_port"],
        ptf_src_ip_vnet2=vnet2["ptf_src_ip"],
    )


def test_vxlan_fg_ecmp_2048_buckets_128_endpoints(ptfhost, common_setup_teardown):
    """
    Scale test: 2048 logical buckets with 128 endpoints.

    With 1000 flows spread across 128 endpoints (~8 flows/endpoint) the
    flow:endpoint ratio is too low for a meaningful even-distribution check,
    so we only validate that:
      - traffic is forwarded (no flow loss)
      - every captured flow lands on a configured endpoint
      - consistent hashing holds: replaying the same flows hits the same
        endpoints as before
    """
    logger.info("Running test_vxlan_fg_ecmp_2048_buckets_128_endpoints")
    setup, duthost, _ = common_setup_teardown

    endpoints = generate_large_endpoint_list(LARGE_ENDPOINT_COUNT)
    set_route_tunnel(duthost, endpoints, bucket_size=BUCKET_SIZE_LARGE)

    run_vxlan_ptf_test(
        ptfhost, endpoints, setup, "create_flows",
        num_packets=NUM_FLOWS,
        check_distribution=False,
        require_all_endpoints_hit=False,
    )
    run_vxlan_ptf_test(
        ptfhost, endpoints, setup, "verify_consistent_hash",
        num_packets=NUM_FLOWS,
        check_distribution=False,
        require_all_endpoints_hit=False,
    )


def test_vxlan_fg_ecmp_2048_buckets_511_endpoints(ptfhost, common_setup_teardown):
    """
    Scale test: 2048 logical buckets with MAX_ENDPOINT_COUNT (511) endpoints
    -- the largest endpoint count the hardware can program (HW caps at 511
    buckets). Same lighter-weight assertions as the 128-endpoint scale test.
    """
    logger.info("Running test_vxlan_fg_ecmp_2048_buckets_511_endpoints")
    setup, duthost, _ = common_setup_teardown

    endpoints = generate_large_endpoint_list(MAX_ENDPOINT_COUNT)
    set_route_tunnel(duthost, endpoints, bucket_size=BUCKET_SIZE_LARGE)

    run_vxlan_ptf_test(
        ptfhost, endpoints, setup, "create_flows",
        num_packets=NUM_FLOWS,
        check_distribution=False,
        require_all_endpoints_hit=False,
    )
    run_vxlan_ptf_test(
        ptfhost, endpoints, setup, "verify_consistent_hash",
        num_packets=NUM_FLOWS,
        check_distribution=False,
        require_all_endpoints_hit=False,
    )


def test_vxlan_fg_ecmp_2048_buckets_512th_endpoint_rejected(ptfhost, common_setup_teardown):
    """
    Negative scale test: with 2048 logical buckets configured the hardware
    still caps the actual bucket count at MAX_HW_BUCKET_SIZE (511). Adding a
    512th endpoint is therefore expected to be rejected: traffic should
    continue to be forwarded only to the original 511 endpoints, and the
    512th (overflow) endpoint should never receive a flow.

    Test flow:
      1. Program 511 endpoints with bucket_size=2048; verify traffic forwards.
      2. Add a 512th endpoint via the same VNET_ROUTE_TUNNEL entry.
      3. Send fresh flows; assert the overflow endpoint receives 0 flows
         while the original 511 continue to receive traffic.
    """
    logger.info("Running test_vxlan_fg_ecmp_2048_buckets_512th_endpoint_rejected")
    setup, duthost, _ = common_setup_teardown

    base_endpoints = generate_large_endpoint_list(MAX_ENDPOINT_COUNT)
    set_route_tunnel(duthost, base_endpoints, bucket_size=BUCKET_SIZE_LARGE)

    # Sanity: the 511-endpoint configuration is functional before we attempt
    # to push past the hardware limit.
    run_vxlan_ptf_test(
        ptfhost, base_endpoints, setup, "create_flows",
        num_packets=NUM_FLOWS,
        check_distribution=False,
        require_all_endpoints_hit=False,
    )

    # Add the 512th (overflow) endpoint. The hardware cannot accommodate it,
    # so the configuration write succeeds at the CONFIG_DB level but the
    # endpoint must never appear in the forwarding decision.
    overflow_endpoints = generate_large_endpoint_list(OVERFLOW_ENDPOINT_COUNT)
    overflow_endpoint = overflow_endpoints[-1]
    assert overflow_endpoint not in base_endpoints, (
        "overflow_endpoint must be the new 512th endpoint"
    )
    set_route_tunnel(duthost, overflow_endpoints, bucket_size=BUCKET_SIZE_LARGE)

    run_vxlan_ptf_test(
        ptfhost, overflow_endpoints, setup, "verify_endpoint_unreachable",
        num_packets=NUM_FLOWS,
        check_distribution=False,
        require_all_endpoints_hit=False,
        forbidden_endpoints=[overflow_endpoint],
    )


def test_vxlan_fg_ecmp_mac_vni(ptfhost, common_setup_teardown):
    """
    Validate that mac_address and vni configured on a VNET_ROUTE_TUNNEL entry
    are used as the inner Ethernet dst MAC and outer VXLAN VNI of the
    encapsulated packets.

    A unique MAC is programmed per endpoint and an override VNI distinct from
    the VNET vni is used so any fallback to the VNET vni will be caught.

    The mac_address field is explicitly deleted in finally — sonic-cfggen
    merges fields, so without an hdel it would leak into subsequent tests
    that program the route without a mac_address.
    """
    logger.info("Running test_vxlan_fg_ecmp_mac_vni")
    setup, duthost, _ = common_setup_teardown

    endpoints = generate_endpoint_list()
    # Deterministic, unique MACs (one per endpoint).
    mac_list = [
        f"52:54:00:{i // 256:02x}:{i % 256:02x}:aa" for i in range(len(endpoints))
    ]
    endpoint_to_mac = dict(zip(endpoints, mac_list))

    set_route_tunnel_with_mac_vni(duthost, endpoints, mac_list, ROUTE_OVERRIDE_VNI)
    try:
        run_vxlan_ptf_test(
            ptfhost,
            endpoints,
            setup,
            "verify_mac_vni",
            num_packets=NUM_FLOWS,
            expected_vni=ROUTE_OVERRIDE_VNI,
            endpoint_to_mac=endpoint_to_mac,
        )
    finally:
        # sonic-cfggen merges fields, so explicitly drop mac_address from
        # CONFIG_DB so subsequent tests' set_route_tunnel calls (which do not
        # set mac_address) start from a clean slate. The vni and endpoints
        # will be overwritten by the next test's own set_route_tunnel call.
        duthost.shell(
            f"sonic-db-cli CONFIG_DB hdel "
            f"'VNET_ROUTE_TUNNEL|{VNET_NAME}|{PREFIX}' mac_address"
        )


def test_transition_regular_to_fg_ecmp(ptfhost, common_setup_teardown):
    """Verify that a regular ECMP route can transition to FG ECMP."""
    logger.info("Running test_transition_regular_to_fg_ecmp")
    setup, duthost, _ = common_setup_teardown
    endpoints = generate_endpoint_list()

    # Phase 1: Downgrade to regular ECMP (remove consistent_hashing_buckets)
    set_route_tunnel_regular(duthost, endpoints)

    # Phase 2: Verify regular ECMP — all endpoints hit, no loss
    run_regular_ecmp_ptf_test(ptfhost, endpoints, setup, num_packets=NUM_FLOWS)

    # Phase 3: Upgrade to FG ECMP (add consistent_hashing_buckets)
    set_route_tunnel(duthost, endpoints)

    # Phase 4: Verify FG ECMP — create flows, check even distribution
    run_vxlan_ptf_test(ptfhost, endpoints, setup, "create_flows", num_packets=NUM_FLOWS)

    # Phase 5: Verify consistent hashing — replay flows, all hit same endpoint
    run_vxlan_ptf_test(ptfhost, endpoints, setup, "verify_consistent_hash", num_packets=NUM_FLOWS)

    # Phase 6: Verify bounded disruption — withdraw one endpoint
    withdrawn = endpoints[-1]
    remaining = endpoints[:-1]
    set_route_tunnel(duthost, remaining)
    run_vxlan_ptf_test(
        ptfhost, remaining, setup, "withdraw_endpoint",
        num_packets=NUM_FLOWS, withdraw_endpoint=withdrawn,
    )


def test_transition_fg_to_regular_ecmp(ptfhost, common_setup_teardown):
    """Verify that an FG ECMP route can transition to regular ECMP."""
    logger.info("Running test_transition_fg_to_regular_ecmp")
    setup, duthost, _ = common_setup_teardown
    endpoints = generate_endpoint_list()

    # Phase 1: Ensure FG ECMP is active (defensive — fixture may have been modified by prior test)
    set_route_tunnel(duthost, endpoints)

    # Phase 2: Verify FG ECMP works — create flows, check distribution
    run_vxlan_ptf_test(ptfhost, endpoints, setup, "create_flows", num_packets=NUM_FLOWS)

    # Phase 3: Verify consistent hashing
    run_vxlan_ptf_test(ptfhost, endpoints, setup, "verify_consistent_hash", num_packets=NUM_FLOWS)

    # Phase 4: Transition to regular ECMP (remove consistent_hashing_buckets)
    set_route_tunnel_regular(duthost, endpoints)

    # Phase 5: Verify regular ECMP — all endpoints hit, no loss
    run_regular_ecmp_ptf_test(ptfhost, endpoints, setup, num_packets=NUM_FLOWS)

    # Phase 6: Verify regular ECMP works with changed endpoints
    changed_endpoints = [f"{ENDPOINT_BASE_IP}{i}" for i in range(5, 5 + NUM_INITIAL_ENDPOINTS)]
    set_route_tunnel_regular(duthost, changed_endpoints)
    run_regular_ecmp_ptf_test(ptfhost, changed_endpoints, setup, num_packets=NUM_FLOWS)
