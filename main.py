import urllib.request
import zipfile
import json
import os

auditStore = 'audit-store.crx'
auditGithub = 'audit-github.crx'

def checkExtension(extensionId, repo):
    result = True

    if (repo.count('/') != 1):
        print('Invalid repo name')
        return False

    try:
        urllib.request.urlretrieve('https://clients2.google.com/service/update2/crx?response=redirect&os=win&arch=x86-64&os_arch=x86-64&nacl_arch=x86-64&prod=chromiumcrx&prodchannel=unknown&prodversion=117.0.0.0&acceptformat=crx2,crx3&x=id%3D'+urlEncode(extensionId)+'%26uc', auditStore)
    except:
        print('Error getting from webstore', extensionId)
        return False
    
    with zipfile.ZipFile(auditStore, mode='r') as extension:
        mv = json.loads(extension.read('manifest.json'))
        trusted = getTrusted(repo, mv['version'])
        
        if (trusted == False):
            print('Error getting repo', repo, 'version', mv['version'])
            return False
        
        # CWS will inject there update_url :)
        mv['update_url'] = 'https://clients2.google.com/service/update2/crx'
        
        trusted.add(json.dumps(mv))

        for name in extension.namelist():
            info = extension.getinfo(name)
            
            # Skip verified_contents.json as its created by CWS
            if (info.is_dir() or name == '_metadata/verified_contents.json'):
                continue
            
            data = extension.read(name)
            
            if (name.endswith('.json')):
                data = cleanJSON(data)
            
            if data not in trusted:
                print('Failed to match', name)
                result = False
        
    os.remove(auditStore)
    
    if (result):
        print('Extension passed', repo , 'version', mv['version'])
    else:
        print('Extension failed', repo , 'version', mv['version'])
    return result


def getTrusted(repo, version):
    trusted = set()
    try:
        urllib.request.urlretrieve('https://github.com/' + urlEncode(repo, '/') + '/archive/refs/tags/' + urlEncode(version) + '.zip', auditGithub)
    except:
        return False
    
    with zipfile.ZipFile(auditGithub, mode='r') as extension:
        for name in extension.namelist():
            info = extension.getinfo(name)
            
            if (info.is_dir()):
                continue
            
            data = extension.read(name)
            if (name.endswith('.json')):
                data = cleanJSON(data)
            
            trusted.add(data)

    os.remove(auditGithub)
    
    return trusted

def cleanJSON(content):
    return json.dumps(json.loads(content))

def urlEncode(value, safe = ''):
    return urllib.parse.quote(value, safe=safe)

checkExtension('bcecldolamfbkgokgpnlpmhjcijglhll', 'NDevTK/AutoPause')
checkExtension('aljkbkjgcllgbhiimdeeefdfocbkolmb', 'NDevTK/RequestIsolation')
