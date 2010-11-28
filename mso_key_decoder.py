import sys
#import string
import math
import _winreg as wr

#b24chrs = (string.digits + string.ascii_uppercase)[:24]
b24chrs = '0123456789ABCDEFGHIJKLMN'

mskey_len = 25
mskey_b24chrs = 'BCDFGHJKMPQRTVWXY2346789'
mskey_reg_root = r'Software\Microsoft\Office'

def chunks(l, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]
        
def b24decode(input, declen=None, map=None):
    if declen is None:
        # each base24 code char takes ~4.585 bits (ln24 / ln2)
        declen = int(math.ceil(8*len(input) / 4.585))
    if map is None:
        map = b24chrs
        
    input = [ord(i) for i in input]
    '''
    # takes less memory (does it piecewise), but more complex
    decoded = []
    for i in range(0,encoded_chars + 1)[::-1]:
        r = 0
        for j in range(0,15)[::-1]:
            r = (r * 256) ^ input[j]
            input[j] = r / 24
            r = r % 24
        
        print b24chrs[r]
        decoded = decoded.append(b24chrs[r])
    
    return decoded[::-1]
    '''
    
    # simple, but eats a ton of memory and probably time if the 
    # encoded string is large
    enc = 0
    for i in input:
        enc = enc * 256 + i
        
    dec = []
    for i in range(declen):
        dec.append(map[enc % 24])
        enc = enc // 24
        
    dec.reverse()
    return ''.join(dec)

def msoKeyDecode(regkey):
    '''Decodes a registry key value, by extracting product key 
    from bytes 52-66 and decoding.
    
    regkey is a string containing the contents of 'DigitalProductID'
    '''
    enckey = regkey[52:66+1][::-1]
    
    deckey = b24decode(enckey, mskey_len, map=mskey_b24chrs)
    
    # translation table for MS base24 characters (eliminates possibly
    # confused characters: I l 1, V U)
    #tran = string.maketrans(b24chrs, mskey_b24chrs)
    #deckey = deckey.translate(tran)
    
    return '-'.join([chunk for chunk in chunks(deckey,5)])
    
def SubKeys(key):
    i = 0
    while True:
        try:
            subkey = wr.EnumKey(key, i)
            yield subkey
        except WindowsError:
            # "WindowsError: [Error 259] No more data is available"
            # exhausted all keys in the given key, end generator
            break
        i += 1
        
def KeyValues(key):
    i = 0
    while True:
        try:
            value = wr.EnumValue(key, i)
            yield value
        except WindowsError:
            # "WindowsError: [Error 259] No more data is available"
            # exhaused all values in the given key, end generator
            break
        i += 1
    
def main(argv=None):
    if argv is None:
        argv = sys.argv
     
    ''' # sample data
    # HKLM/Software/Microsoft/Office/11.0/
    #         Registration/{blahblah}/DigitalProductID
    enc =   range(52) +            [ 15 bytes of data... ]
    ''.join([chr(i) for i in enc])
    
    print msoKeyDecode(enc)
    '''
    
    mso_root_key = wr.OpenKey(wr.HKEY_LOCAL_MACHINE, mskey_reg_root)
    
    for subkey in SubKeys(mso_root_key):
        for subsubkey in SubKeys(
                wr.OpenKey(mso_root_key, subkey)):
            for subsubsubkey in SubKeys(
                    wr.OpenKey(
                    wr.OpenKey(mso_root_key,
                               subkey), 
                               subsubkey)):
                dpid_found = False
                for keyvalue in KeyValues(
                        wr.OpenKey(
                        wr.OpenKey(
                        wr.OpenKey(mso_root_key,
                                   subkey),
                                   subsubkey),
                                   subsubsubkey)):
                    if keyvalue[0] == 'DigitalProductID':
                        dpid_found = True
                        dpid = keyvalue
                    if keyvalue[0] == 'ProductName':
                        name = keyvalue
                        
                if dpid_found:
                    print "Product Name: %s\n\t Key: %s\n" % (name[1], msoKeyDecode(dpid[1]))
        
if __name__ == "__main__":
    sys.exit(main())