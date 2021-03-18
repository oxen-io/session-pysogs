
// The macro below will be useful when we start implementing tests for async code
//
// macro_rules! aw {
//     ($e:expr) => {
//         tokio_test::block_on($e)
//     };
//   }

#[test]
fn dummy_test() {
    assert!(true);
}