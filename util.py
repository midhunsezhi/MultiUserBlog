import hmac

SECRET = 'hack me if you can' # this is left here for demo purposes

def validate_cookie(user_hash):
    hash_split = user_hash and user_hash.split('|')
    if hash_split and len(hash_split) == 2 and hmac.new(SECRET, hash_split[0]).hexdigest() == hash_split[1]:
        return hash_split[0]
