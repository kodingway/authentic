import logging

SESSION_DUMP_KEY = 'saml2_idp_session_dump'

logger = logging.getLogger(__file__)

def load_session(request, profile):
    session_dump = request.session.get(SESSION_DUMP_KEY)
    if not session_dump:
        return
    logger.debug('loading session dump %r', session_dump)
    profile.setSessionFromDump(session_dump)

def save_session(request, profile):
    if not profile.isSessionDirty:
        return
    session_dump = profile.session.dump()
    logger.debug('saving session dump %r', session_dump)
    request.session[SESSION_DUMP_KEY] = session_dump
