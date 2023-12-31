/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// NOTE: new type added here
const bit<16> TYPE_MYTUNNEL = 0x1212;
const bit<16> TYPE_IPV4 = 0x800;

#define VECTOR_SIZE 4

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header myTunnel_t {
    bit<16> proto_id;
    bit<16> dst_id;
    bit<64> count;
}

header vector_t {
    bit<1>    bos;
    bit<31>   val;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    /* empty */
    bit<64> count_val;
}

// NOTE: Added new header type to headers struct
struct headers {
    ethernet_t              ethernet;
    myTunnel_t              myTunnel;
    vector_t[VECTOR_SIZE]   vector;
    ipv4_t                  ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

// TODO: Update the parser to parse the myTunnel header as well
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_MYTUNNEL : parse_myTunnel;
            TYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_myTunnel {
        packet.extract(hdr.myTunnel);
        transition select(hdr.myTunnel.proto_id) {
            0x1234 : parse_vector;
            default : accept;
        }

    }

    state parse_vector {
        packet.extract(hdr.vector.next);
        transition select(hdr.vector.last.bos) {
            0 : parse_vector;
            default : parse_ipv4;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    register<bit<31>>(4) sum;
    register<bit<64>>(1) count;

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action addTwo_elements(bit<32> index, bit<31> value) {
        // temporary variable for addition
        bit<31> temp;

        // read register value to temp variable
        sum.read(temp, index);

        // add vector element in header to temp
        temp = temp + value;
        
        // write the sum in temp to register
        sum.write(index, temp);

        // send back the new sum value in the header
        hdr.vector[index].val = temp;
    }

    action reset_count() {
        count.write(0, 0);
    }

    action read_count() {
        count.read(meta.count_val, 0);
    }

    action increment_count() {
        // temporary variable for addition
        bit<64> temp;

        // read register value to temp variable
        count.read(temp, 0);

        // add vector element in header to temp
        temp = temp + 1;
        
        // write the sum in temp to register
        count.write(0, temp);

        // send back the new sum value in the header
        hdr.myTunnel.count = temp;

        // update count value in header
        read_count();
    }

    action myTunnel_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;

        /* increment packet counter */
        increment_count();

        read_count();
    }

    action aggregate() {
        /* vector aggregation */
        addTwo_elements(0, hdr.vector[0].val);
        addTwo_elements(1, hdr.vector[1].val);
        addTwo_elements(2, hdr.vector[2].val);
        addTwo_elements(3, hdr.vector[3].val);
    }

    // TODO: declare a new table: myTunnel_exact
    // TODO: also remember to add table entries!
    table myTunnel_exact {
        key = {
            hdr.myTunnel.dst_id : exact;
        }
        actions = {
            myTunnel_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    action multicast() {
        standard_metadata.mcast_grp = 1;
        reset_count();
    }

    table mcast_exact {
        key = {
            meta.count_val : exact;
        }
        actions = {
            multicast;
            drop;
        }
        default_action = drop();
    }

    action l2_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        increment_count();
        aggregate();
    }

    table l2_exact {
        key = {
            hdr.ethernet.dstAddr : exact;
        }
        actions = {
            l2_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }


    apply {
        if (hdr.ethernet.isValid()) {
            l2_exact.apply();
            mcast_exact.apply();
        } else if (hdr.myTunnel.isValid()) {
            myTunnel_exact.apply();
        
        } else if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    apply { 
        // Prune multicast packet to ingress port to preventing loop
        if (standard_metadata.egress_port == standard_metadata.ingress_port)
            drop();
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        // TODO: emit myTunnel header as well
        packet.emit(hdr.myTunnel);
        packet.emit(hdr.vector);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
