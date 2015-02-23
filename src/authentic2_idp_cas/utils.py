import random
import string

ALPHABET = string.letters+string.digits+'-'

def make_id(prefix='', length=29):
    '''Generate CAS tickets identifiers'''
    l = length-len(prefix)
    content = ( random.SystemRandom().choice(ALPHABET) for x in range(l) )
    return prefix + ''.join(content)
