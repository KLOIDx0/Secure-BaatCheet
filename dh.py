import secrets
from dh_params import P, G


def make_keypair():
    # Private secret: random integer in [2, P-2]
    a = secrets.randbelow(P - 3) + 2
    # Public value: G^a mod P
    A = pow(G, a, P)
    return a, A

def shared_secret(my_private, their_public):
    # K = their_public^my_private mod P
    return pow(their_public, my_private, P)
