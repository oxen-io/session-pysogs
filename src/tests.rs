
macro_rules! aw {
    ($e:expr) => {
        tokio_test::block_on($e)
    };
  }

#[test]
fn dummy_test() {
    assert!(true);
}