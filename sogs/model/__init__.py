from .. import config

if config.PROFANITY_FILTER:
    import better_profanity

    if config.PROFANITY_CUSTOM:
        better_profanity.profanity.load_censor_words_from_file(config.PROFANITY_CUSTOM)
    else:
        better_profanity.profanity.load_censor_words()
