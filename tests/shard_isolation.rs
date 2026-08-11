//! The whole point of the shard archives: symbol-prefixed copies of the
//! stack must own SEPARATE globals. A runtime flag flipped through one
//! copy's accessors must be invisible through every other copy's, in both
//! directions — anything less means the rename header missed a symbol and
//! two "instances" alias the same state.

// The extern block below bypasses the crate's bindings on purpose (shard
// symbols have no bindings yet), but the native archives ride on the crate's
// rlib metadata — an unused crate is not linked, so anchor it explicitly.
use lwip as _;

extern "C" {
    fn lwip_init();
    fn lwip_rs_set_tcp_tx_partial_checksum(enabled: i32);
    fn lwip_rs_tcp_tx_partial_checksum() -> i32;

    fn panda_shard1_lwip_init();
    fn panda_shard1_lwip_rs_set_tcp_tx_partial_checksum(enabled: i32);
    fn panda_shard1_lwip_rs_tcp_tx_partial_checksum() -> i32;

    fn panda_shard2_lwip_init();
    fn panda_shard2_lwip_rs_tcp_tx_partial_checksum() -> i32;

    fn panda_shard3_lwip_init();
    fn panda_shard3_lwip_rs_tcp_tx_partial_checksum() -> i32;
}

#[test]
fn shard_stacks_own_globals_independent_of_the_primary() {
    unsafe {
        // This integration test is its own process; nothing else touches
        // lwIP here, so raw init calls need no LWIP_MUTEX choreography.
        lwip_init();
        panda_shard1_lwip_init();
        panda_shard2_lwip_init();
        panda_shard3_lwip_init();

        // Primary -> shards: a primary-side write must not leak into any shard.
        lwip_rs_set_tcp_tx_partial_checksum(1);
        assert_eq!(lwip_rs_tcp_tx_partial_checksum(), 1);
        assert_eq!(
            panda_shard1_lwip_rs_tcp_tx_partial_checksum(),
            0,
            "shard1 aliases the primary stack's globals"
        );
        assert_eq!(
            panda_shard2_lwip_rs_tcp_tx_partial_checksum(),
            0,
            "shard2 aliases the primary stack's globals"
        );
        assert_eq!(
            panda_shard3_lwip_rs_tcp_tx_partial_checksum(),
            0,
            "shard3 aliases the primary stack's globals"
        );

        // Shard -> primary and shard -> shard: the reverse must hold too.
        panda_shard1_lwip_rs_set_tcp_tx_partial_checksum(1);
        lwip_rs_set_tcp_tx_partial_checksum(0);
        assert_eq!(
            panda_shard1_lwip_rs_tcp_tx_partial_checksum(),
            1,
            "the primary stack's write clobbered shard1"
        );
        assert_eq!(lwip_rs_tcp_tx_partial_checksum(), 0);
        assert_eq!(
            panda_shard2_lwip_rs_tcp_tx_partial_checksum(),
            0,
            "shard1's write leaked into shard2"
        );
    }
}
