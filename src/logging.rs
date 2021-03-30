use log::LevelFilter;
use log4rs::{
    append::{
        console::ConsoleAppender,
        rolling_file::{policy::compound, RollingFileAppender},
    },
    config::{Appender, Logger, Root},
    encode::pattern::PatternEncoder,
    filter::threshold::ThresholdFilter,
};

pub(crate) fn init(log_file: Option<String>) {
    let console_level = LevelFilter::Debug;
    let file_level = LevelFilter::Info;

    let stdout_appender = {
        let encoder = Box::new(PatternEncoder::new("{h({l})} {d} - {m}{n}"));
        let stdout = ConsoleAppender::builder().encoder(encoder).build();
        let filter = Box::new(ThresholdFilter::new(console_level));
        Appender::builder().filter(filter).build("stdout", Box::new(stdout))
    };

    let mut root = Root::builder().appender("stdout");

    // increase chainflip logging level to debug
    let chainflip = Logger::builder().build("session_open_group_server", LevelFilter::Debug);

    let mut config_builder = log4rs::Config::builder().logger(chainflip).appender(stdout_appender);

    if let Some(log_file) = log_file {
        // Rotate log files every ~50MB keeping 1 archived
        let size_trigger = compound::trigger::size::SizeTrigger::new(50_000_000);
        let roller = compound::roll::fixed_window::FixedWindowRoller::builder()
            .build(&format!("{}-archive.{{}}", &log_file), 1)
            .unwrap();
        let roll_policy = compound::CompoundPolicy::new(Box::new(size_trigger), Box::new(roller));

        // Print to the file at Info level
        let file_appender =
            RollingFileAppender::builder().build(&log_file, Box::new(roll_policy)).unwrap();
        let filter = Box::new(ThresholdFilter::new(file_level));
        let file_appender =
            Appender::builder().filter(filter).build("file", Box::new(file_appender));

        config_builder = config_builder.appender(file_appender);

        root = root.appender("file");
    }

    let root = root.build(file_level);

    let config = config_builder.build(root).unwrap();

    let _ = log4rs::init_config(config).expect("Error initialising log configuration");
}
