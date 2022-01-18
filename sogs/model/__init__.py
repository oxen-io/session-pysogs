from .. import config

if config.PROFANITY_FILTER:
    import better_profanity

    if config.PROFANITY_CUSTOM:
        better_profanity.profanity.load_censor_words_from_file(config.PROFANITY_CUSTOM)
    else:
        better_profanity.profanity.load_censor_words()


# Set of free-form strings that indicate the capability of this sogs server.  As new features are
# added that a Session client might want to know about a string still be added here to allow session
# to identify the server's capabilities and act accordingly.
capabilities = {
    'sogs',  # Basic sogs capabilities
    # 'newcap',  # Add here
}
