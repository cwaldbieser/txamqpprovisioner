
from ConfigParser import SafeConfigParser
from  cStringIO import StringIO
import os.path

def load_config(config_file=None, defaults=None):
    syspath = "/etc/txamqpprovisioners/provisioners.cfg"
    homepath = os.path.expanduser("~/.txamqpprovisionersrc/provisioners.cfg")
    files = [syspath, homepath]
    if config_file is not None:
        files.append(config_file)
    scp = SafeConfigParser()
    if defaults is not None:
        buf = StringIO(defaults)
        scp.readfp(buf)
    scp.read(files)
    return scp
    
def section2dict(scp, section):
    d = {}
    for option in scp.options(section):
        d[option] = scp.get(section, option)
    return d
