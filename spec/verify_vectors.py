#!/usr/bin/env python3
"""Kavach v1 conformance fixtures/reference codec (protocol revision 4, wire version 5). TEST ONLY, not a production SDK.
Derived from the SS5 revision 2 package (spec/vectors-rev2) with four changes: key-list lifetime 30 days,
record flag bit 0 reserved, type 5 retired, 49-byte vault entry. Wire labels keep the SealedStream/5/ prefix.
Run: python verify_vectors.py [--generate]
Dependencies: PyNaCl==1.6.0, pycryptodome==3.23.0, cryptography>=44.
--generate rewrites vectors.json; default verifies the frozen fixture.
"""
import hashlib, json, re, struct, sys, base64
from pathlib import Path
from nacl import bindings as sodium
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError, CryptoError
from Crypto.Cipher import ChaCha20_Poly1305
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

BASE=Path(__file__).resolve().parent
V=5
MAX_PAYLOAD=4096

def C(label): return ('SealedStream/5/'+label).encode('ascii')+b'\0'
def H(data): return hashlib.blake2b(data,digest_size=32).digest()
def D(seed,label): return hashlib.blake2b(C(label),key=seed,digest_size=32).digest()
def U8(n): return struct.pack('>B',n)
def U16(n): return struct.pack('>H',n)
def U32(n): return struct.pack('>I',n)
def U64(n): return struct.pack('>Q',n)
def ID(s):
    b=s.encode('ascii')
    if not re.fullmatch(rb'[A-Za-z0-9_-]{1,64}',b): raise ValueError('BAD_ID')
    return U8(len(b))+b

def doc_hash(body): return H(C('doc-hash')+body)
def identity_id(name,ak): return H(C('identity')+ID(name)+ak)
def stream_id(iid,device_id): return H(C('stream')+iid+device_id)
def sign(sk,label,body): return body+sk.sign(C(label)+body).signature

def identity(name,a_seed,d_seed,generation=1,device_id=None):
    a=SigningKey(a_seed); d=SigningKey(D(d_seed,'device-sign'))
    epk,esk=sodium.crypto_box_seed_keypair(D(d_seed,'device-box'))
    iid=identity_id(name,bytes(a.verify_key))
    device_id=device_id or H(C('fixture-device-id')+d_seed)[:16]
    body=bytes([5,1])+ID(name)+bytes(a.verify_key)+U64(generation)+device_id+bytes(d.verify_key)+epk
    return dict(name=name,a=a,d=d,epk=epk,esk=esk,iid=iid,generation=generation,device_id=device_id,wire=sign(a,'account-sig',body))

class Bad(ValueError): pass
class Reader:
    def __init__(self,data): self.data=data; self.i=0
    def take(self,n):
        if n<0 or self.i+n>len(self.data): raise Bad('MALFORMED')
        x=self.data[self.i:self.i+n]; self.i+=n; return x
    def n(self,n): return int.from_bytes(self.take(n),'big')
    def end(self):
        if self.i!=len(self.data): raise Bad('MALFORMED')

def parse(wire):
    if len(wire)>16384: raise Bad('SIZE_LIMIT')
    r=Reader(wire)
    if r.n(1)!=5: raise Bad('UNSUPPORTED_VERSION')
    t=r.n(1); d={'type':t}
    if t==1:
        n=r.n(1); name=r.take(n)
        if not re.fullmatch(rb'[A-Za-z0-9_-]{1,64}',name): raise Bad('MALFORMED')
        d.update(name=name.decode(),ak=r.take(32),generation=r.n(8),device_id=r.take(16),dpk=r.take(32),epk=r.take(32))
        if d['generation']==0 or d['device_id']==bytes(16): raise Bad('MALFORMED')
    elif t==2:
        d.update(circle=r.take(16),owner=r.take(32),revision=r.n(8)); n=r.n(2)
        if d['revision']==0 or not 1<=n<=100: raise Bad('MALFORMED')
        d['members']=[r.take(32) for _ in range(n)]
        if d['members']!=sorted(set(d['members'])) or d['owner'] not in d['members']: raise Bad('MALFORMED')
    elif t==3:
        d.update(stream=r.take(32),author=r.take(32),author_certificate=r.take(32),epoch=r.n(4),created=r.n(8),commit=r.take(32)); n=r.n(2)
        if d['epoch']==0 or not 1<=n<=100: raise Bad('MALFORMED')
        d['audience']=[(r.take(32),r.take(32),r.take(32)) for _ in range(n)]
        ids=[x[0] for x in d['audience']]
        if ids!=sorted(set(ids)) or d['author'] not in ids: raise Bad('MALFORMED')
    elif t==4:
        d.update(stream=r.take(32),epoch=r.n(4),counter=r.n(4),sent=r.n(8),flags=r.n(1))
        if d['epoch']==0 or d['flags']&~6: raise Bad('MALFORMED')
        d['header_class']=(d['flags']>>1)&3  # revision 8: the kind is inside the envelope; the header shows only the declared class
        d['header']=wire[:r.i]; d['nonce']=r.take(24); n=r.n(4)
        if not 26<=n<=4122: raise Bad('SIZE_LIMIT')
        d['ciphertext']=r.take(n)
    elif t==7:
        name=r.take(r.n(1))
        if not re.fullmatch(rb'[A-Za-z0-9_-]{1,64}',name): raise Bad('MALFORMED')
        d.update(name=name.decode(),old=r.take(32),new=r.take(32),reset_id=r.take(16),issued=r.n(8),authority_id=r.take(16))
        if d['old']==d['new']: raise Bad('MALFORMED')
    elif t==8:
        d.update(version=r.n(8),issued=r.n(8),expires=r.n(8)); n=r.n(1)
        if d['version']==0 or n>8 or not 0<d['expires']-d['issued']<=2592000000: raise Bad('MALFORMED')
        d['keys']=[(r.take(16),r.take(32)) for _ in range(n)]
        ids=[i for i,k in d['keys']]; keys=[k for i,k in d['keys']]
        if ids!=sorted(set(ids)) or bytes(16) in ids or len(set(keys))!=n: raise Bad('MALFORMED')
        if any(not sodium.crypto_core_ed25519_is_valid_point(k) for k in keys): raise Bad('INVALID_KEY')
    else: raise Bad('UNSUPPORTED_TYPE')
    d['body']=wire[:r.i]; d['sig']=r.take(64); r.end(); return d

LABELS={1:'account-sig',2:'snapshot-sig',3:'epoch-sig',4:'record-sig',7:'reset-sig',8:'reset-keys-sig'}
def verify(wire,pk=None):
    d=parse(wire)
    if d['type']==1: pk=d['ak']
    if pk is None: raise Bad('MISSING_IDENTITY')
    if not sodium.crypto_core_ed25519_is_valid_point(pk): raise Bad('INVALID_KEY')
    try: VerifyKey(pk).verify(C(LABELS[d['type']])+d['body'],d['sig'])
    except (BadSignatureError,ValueError): raise Bad('BAD_SIGNATURE')
    if d['type']==1:
        if not sodium.crypto_core_ed25519_is_valid_point(d['dpk']): raise Bad('INVALID_KEY')
        # Fixed non-secret scalar probes X25519 input; reject low-order/all-zero shared secrets.
        try: sodium.crypto_scalarmult(bytes([0x42])*32,d['epk'])
        except (CryptoError,RuntimeError): raise Bad('INVALID_KEY')
    return d

def reset_key_list(root,version,issued,expires,keys):
    body=b'\x05\x08'+U64(version)+U64(issued)+U64(expires)+U8(len(keys))+b''.join(i+k for i,k in keys)
    return sign(root,'reset-keys-sig',body)

class ResetTrust:
    """Reference acceptance model, not a trusted clock or durable adapter."""
    def __init__(self,root,minimum=1):
        self.root=root; self.minimum=minimum; self.current=None; self.time=0
        self.accepted=set(); self.events={}; self.retired=set()
    def clock(self,now):
        if now is None or now<self.time: raise Bad('RESET_CLOCK_UNTRUSTED')
    def install(self,wire,now):
        d=verify(wire,self.root)
        if d['type']!=8: raise Bad('MALFORMED')
        if any(k==self.root for i,k in d['keys']): raise Bad('INVALID_KEY')
        if d['version']<self.minimum or (self.current and d['version']<self.current['version']): raise Bad('ROLLBACK')
        if self.current and d['version']==self.current['version'] and doc_hash(d['body'])!=doc_hash(self.current['body']): raise Bad('EQUIVOCATION')
        self.clock(now)
        if not d['issued']<=now<d['expires']: raise Bad('RESET_KEYS_REQUIRED')
        result='DUPLICATE' if self.current and d['version']==self.current['version'] else 'INSTALLED'
        self.current=d; self.time=now
        return result
    def apply(self,wire,new_certificate,name,current_identity,now):
        if H(wire) in self.accepted: return 'DUPLICATE'
        self.clock(now)
        if not self.current or not self.current['issued']<=now<self.current['expires']: raise Bad('RESET_KEYS_REQUIRED')
        d=parse(wire)
        if d['type']!=7: raise Bad('MALFORMED')
        keys=dict(self.current['keys'])
        if d['authority_id'] not in keys: raise Bad('RESET_KEY_REVOKED')
        d=verify(wire,keys[d['authority_id']]); cert=verify(new_certificate)
        if cert['type']!=1: raise Bad('RESET_BINDING')
        binding=(d['name'],d['old'],d['new'])
        if d['name']!=name or cert['name']!=name or identity_id(name,cert['ak'])!=d['new']: raise Bad('RESET_BINDING')
        if d['reset_id'] in self.events:
            if self.events[d['reset_id']]!=binding: raise Bad('RESET_BINDING')
            result='DUPLICATE'
        else:
            if d['old']!=current_identity or d['new'] in self.retired: raise Bad('RESET_BINDING')
            result='ACCOUNT_KEY_CHANGED'
        self.accepted.add(H(wire)); self.events[d['reset_id']]=binding; self.retired.add(d['old']); self.time=now
        return result

def accept_device_certificate(current,candidate):
    old=verify(current);new=verify(candidate)
    if old['name']!=new['name'] or old['ak']!=new['ak']: raise Bad('ACCOUNT_KEY_CHANGED')
    if new['generation']<old['generation']: raise Bad('DEVICE_ROLLBACK')
    if new['generation']==old['generation']:
        if doc_hash(new['body'])!=doc_hash(old['body']):raise Bad('EQUIVOCATION')
        return 'DUPLICATE'
    if new['device_id']==old['device_id']:raise Bad('DEVICE_ID_REUSED')
    return 'ACCEPTED'

def sealed_fixture(key,recipient,ephemeral_seed):
    epk,esk=sodium.crypto_box_seed_keypair(ephemeral_seed)
    nonce=hashlib.blake2b(epk+recipient['epk'],digest_size=24).digest()
    box=epk+sodium.crypto_box(key,nonce,recipient['epk'],esk)
    assert sodium.crypto_box_seal_open(box,recipient['epk'],recipient['esk'])==key
    return box,epk,nonce

def snapshot(owner,circle,revision,members):
    body=b'\x05\x02'+circle+owner['iid']+U64(revision)+U16(len(members))+b''.join(sorted(members))
    return sign(owner['a'],'snapshot-sig',body)

def manifest(author,epoch,created,key,wraps,recipients):
    stream=stream_id(author['iid'],author['device_id'])
    commit=H(C('epoch-key')+stream+U32(epoch)+key)
    rows=b''.join(i+doc_hash(recipients[i]['wire'][:-64])+H(C('wrap')+w) for i,w in sorted(wraps.items()))
    body=b'\x05\x03'+stream+author['iid']+doc_hash(author['wire'][:-64])+U32(epoch)+U64(created)+commit+U16(len(wraps))+rows
    return sign(author['d'],'epoch-sig',body)

def envelope(kind,event,payload):
    """Revision 8: u8(1) || u8(kind) || u64(eventTime or 0) || payload, the plaintext under the AEAD."""
    if len(payload)>4096: raise Bad('SIZE_LIMIT')
    return U8(1)+U8(kind)+U64(event or 0)+payload

def open_envelope(plaintext):
    if len(plaintext)<10 or plaintext[0]!=1: raise Bad('MALFORMED')
    kind=plaintext[1]; event=int.from_bytes(plaintext[2:10],'big')
    return kind,(event or None),plaintext[10:]

def record(author,epoch,counter,sent,header_class,nonce,key,payload,kind=0,event=None,plaintext=None):
    plaintext=envelope(kind,event,payload) if plaintext is None else plaintext
    header=b'\x05\x04'+stream_id(author['iid'],author['device_id'])+U32(epoch)+U32(counter)+U64(sent)+U8(header_class<<1)
    aad=C('record-aad')+header
    ct=sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext,aad,nonce,key)
    independent=ChaCha20_Poly1305.new(key=key,nonce=nonce); independent.update(aad)
    ct2,tag2=independent.encrypt_and_digest(plaintext)
    assert ct==ct2+tag2
    body=header+nonce+U32(len(ct))+ct
    wire=sign(author['d'],'record-sig',body)
    rid=H(C('record-id')+stream_id(author['iid'],author['device_id'])+U32(epoch)+U32(counter))
    return wire, aad, rid

def retired_intent_wire(requester,owner,circle,request,issued,expires,action=1):
    # Type 5 (MembershipIntent) existed in revision 2 and is retired; a parser rejects it before any signature check.
    body=b'\x05\x05'+U8(action)+circle+owner['iid']+requester['iid']+request+U64(issued)+U64(expires)
    return sign(requester['a'],'intent-sig',body)

def vault(account,recovery_key,revision,nonce,entries):
    header=b'\x05\x06'+ID(account['name'])+bytes(account['a'].verify_key)+U64(revision)
    inner=bytes(account['a'])+U64(account['generation'])+doc_hash(account['wire'][:-64])+U16(len(entries))
    for circle,owner,enabled in sorted(entries): inner+=circle+owner+U8(enabled)
    aad=C('vault-aad')+header
    ct=sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(inner,aad,nonce,recovery_key)
    other=ChaCha20_Poly1305.new(key=recovery_key,nonce=nonce);other.update(aad)
    c,t=other.encrypt_and_digest(inner);assert c+t==ct
    return header+nonce+U32(len(ct))+ct,inner,aad

def open_vault(wire,recovery_key,expected_name,expected_ak):
    if len(wire)>16384: raise Bad('SIZE_LIMIT')
    r=Reader(wire)
    if r.take(2)!=b'\x05\x06': raise Bad('MALFORMED')
    name=r.take(r.n(1));ak=r.take(32);rev=r.n(8)
    if name!=expected_name.encode() or ak!=expected_ak or rev==0: raise Bad('VAULT_BINDING')
    header=wire[:r.i];nonce=r.take(24);n=r.n(4)
    if not 90<=n<=4990: raise Bad('SIZE_LIMIT')
    ct=r.take(n);r.end()
    try: plain=sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(ct,C('vault-aad')+header,nonce,recovery_key)
    except CryptoError: raise Bad('DECRYPT_FAILED')
    p=Reader(plain);seed=p.take(32);generation=p.n(8);cert=p.take(32);count=p.n(2)
    if bytes(SigningKey(seed).verify_key)!=ak or generation==0 or count>100: raise Bad('MALFORMED')
    entries=[]
    for _ in range(count):
        row=(p.take(16),p.take(32),p.n(1))
        if row[2] not in (0,1): raise Bad('MALFORMED')
        entries.append(row)
    p.end()
    ids=[x[0] for x in entries]
    if ids!=sorted(set(ids)): raise Bad('MALFORMED')
    return seed,generation,cert,entries

def verify_manifest_current(wire,author):
    p=parse(wire);ch=doc_hash(author['wire'][:-64])
    if p['author_certificate']!=ch: raise Bad('SUPERSEDED_DEVICE')
    verify(wire,bytes(author['d'].verify_key))
    if p['author']!=author['iid'] or p['stream']!=stream_id(author['iid'],author['device_id']): raise Bad('MALFORMED')
    self_row=[r for r in p['audience'] if r[0]==author['iid']][0]
    if self_row[1]!=ch: raise Bad('MALFORMED')
    return p

def open_epoch(wire,author,recipient,wrap):
    p=verify_manifest_current(wire,author)
    rows=[r for r in p['audience'] if r[0]==recipient['iid']]
    if not rows: raise Bad('NOT_AUTHORIZED')
    row=rows[0]
    if row[1]!=doc_hash(recipient['wire'][:-64]): raise Bad('KEY_PENDING')
    if row[2]!=H(C('wrap')+wrap): raise Bad('WRAP_HASH_MISMATCH')
    try:key=sodium.crypto_box_seal_open(wrap,recipient['epk'],recipient['esk'])
    except CryptoError:raise Bad('DECRYPT_FAILED')
    if H(C('epoch-key')+p['stream']+U32(p['epoch'])+key)!=p['commit']:raise Bad('KEY_COMMITMENT_MISMATCH')
    return key

def recovery_text(key):
    return 'KV1R-'+base64.urlsafe_b64encode(key).decode().rstrip('=')

def parse_recovery_text(text):
    if not text.startswith('KV1R-'):raise Bad('MALFORMED')
    value=text[5:]
    if not re.fullmatch(r'[A-Za-z0-9_-]+',value):raise Bad('MALFORMED')
    try:raw=base64.urlsafe_b64decode(value+'='*((-len(value))%4))
    except Exception:raise Bad('MALFORMED')
    if len(raw)!=32 or base64.urlsafe_b64encode(raw).decode().rstrip('=')!=value:raise Bad('MALFORMED')
    return raw

def location(lat,lon,accuracy,captured,status):
    return b'\x01'+struct.pack('>iiIQB',lat,lon,accuracy,captured,status)

def parse_location(p):
    if len(p)!=22 or p[0]!=1: raise Bad('BAD_PAYLOAD')
    lat,lon,acc,ts,status=struct.unpack('>iiIQB',p[1:])
    if not -900000000<=lat<=900000000 or not -1800000000<=lon<=1800000000 or not 0<=acc<=100000000 or status not in [0,1,2] or (status==2 and (lat!=0 or lon!=0 or acc!=0)): raise Bad('BAD_PAYLOAD')
    return lat,lon,acc,ts,status

# Tiny executable security-state model, deliberately not a persistence adapter.
class Model:
    def __init__(self):
        self.desired=1; self.epoch=0; self.pending=None; self.active=None
        self.next=0; self.queue=[]; self.latest=None; self.history={}; self.snapshots={}
    def prepare(self,wire):
        assert self.pending is None
        self.pending=(self.epoch+1,self.desired,wire)
    def change(self):
        self.desired+=1; self.active=None; self.queue=[]
    def commit(self):
        assert self.pending
        e,r,w=self.pending; self.epoch=e; self.pending=None
        if r==self.desired: self.active=e; self.next=0; return 'PROMOTED'
        return 'OBSOLETE'
    def enqueue(self):
        if self.active is None: return 'ROTATION_REQUIRED'
        if self.next>0xffffffff:
            self.change(); return 'COUNTER_EXHAUSTED'
        row=(self.active,self.next,self.desired); self.next+=1; self.queue.append(row); return row
    def snapshot(self,circle,rev,h):
        old=self.snapshots.get(circle)
        if old and rev<old[0]: return 'ROLLBACK'
        if old and rev==old[0]: return 'DUPLICATE' if h==old[1] else 'EQUIVOCATION'
        self.snapshots[circle]=(rev,h); self.change(); return 'ACCEPTED'
    def receive_latest(self,slot,h):
        if slot in self.history and self.history[slot]!=h:return 'EQUIVOCATION'
        self.history[slot]=h
        if self.latest:
            if slot<self.latest[0]: return 'HISTORY_ONLY'
            if slot==self.latest[0]: return 'DUPLICATE' if self.latest[1]==h else 'EQUIVOCATION'
        self.latest=(slot,h); return 'UPDATED'

def run_state_tests():
    out=[]
    def result(name,events,actual,expected):
        assert actual==expected,(name,actual,expected)
        out.append(dict(name=name,events=events,expected=expected))
    m=Model(); m.prepare(b'exact bytes'); before=m.pending; retry=m.pending
    result('S01_exact_retry',['prepare','lost response','restart/retry'],retry==before,True)
    m.change(); result('S02_obsolete_commit',['prepare r1','membership r2','commit epoch1'],m.commit(),'OBSOLETE')
    result('S03_no_obsolete_seal',['enqueue after S02'],m.enqueue(),'ROTATION_REQUIRED')
    m.prepare(b'epoch2'); result('S04_promote_next',['prepare r2','commit epoch2'],m.commit(),'PROMOTED')
    result('S05_no_counter_reuse',['enqueue','restart preserved store','enqueue'],[m.enqueue()[:2],m.enqueue()[:2]],[(2,0),(2,1)])
    m.change(); result('S06_drop_stale_queue',['known change'],len(m.queue),0)
    result('S07_new_snapshot',['rev12'],m.snapshot('c',12,b'a'),'ACCEPTED')
    result('S08_old_snapshot',['rev11'],m.snapshot('c',11,b'b'),'ROLLBACK')
    result('S09_snapshot_same_body',['rev12 same body'],m.snapshot('c',12,b'a'),'DUPLICATE')
    result('S10_snapshot_conflict',['rev12 different body'],m.snapshot('c',12,b'b'),'EQUIVOCATION')
    result('S11_latest',['receive (epoch 1, counter 7)'],m.receive_latest((1,7),b'a'),'UPDATED')
    result('S12_duplicate',['same latest wire'],m.receive_latest((1,7),b'a'),'DUPLICATE')
    result('S13_slot_conflict',['different valid wire same slot'],m.receive_latest((1,7),b'b'),'EQUIVOCATION')
    m.prepare(b'e3'); m.commit(); m.next=0xffffffff
    result('S14_final_counter',['enqueue UINT32_MAX'],m.enqueue()[:2],(3,0xffffffff))
    result('S15_counter_overflow',['enqueue again'],m.enqueue(),'COUNTER_EXHAUSTED')
    assert m.active is None and not m.queue
    result('S16_old_location',['receive (epoch 1, counter 6)'],m.receive_latest((1,6),b'old'),'HISTORY_ONLY')
    assert (1,6) in m.history and (1,7) in m.history
    m.prepare(b'e4');m.commit();m.enqueue();m.enqueue()
    result('S17_durable_queue',['two unsent locations'],{'count':len(m.queue),'tuple':list(m.queue[0][:2])},{'count':2,'tuple':[4,0]})
    return out

def build():
    alice=identity('alice',bytes(range(32)),bytes(range(32,64)))
    bob=identity('bob',bytes(range(64,96)),bytes(range(96,128)))
    identities=[alice,bob]; key=bytes(range(160,192)); circle=bytes(range(16)); now=1700000000000
    wraps={}; wrap_detail=[]
    for j,who in enumerate(identities):
        seed=bytes(range(192+j*32,224+j*32))
        box,epk,nonce=sealed_fixture(key,who,seed); wraps[who['iid']]=box
        wrap_detail.append(dict(recipient_identity=who['iid'].hex(),ephemeral_seed=seed.hex(),ephemeral_public=epk.hex(),nonce=nonce.hex(),sealed_box=box.hex(),wrap_hash=H(C('wrap')+box).hex()))
    ss=snapshot(alice,circle,1,[p['iid'] for p in identities])
    mf=manifest(alice,1,now,key,wraps,{p['iid']:p for p in identities})
    for recipient in identities: assert open_epoch(mf,alice,recipient,wraps[recipient['iid']])==key
    payload=location(377749000,-1224194000,5000,now-123,0)
    rec,aad,rid=record(alice,1,0,now,0,bytes(range(24)),key,payload,kind=0,event=now-123)  # the event time is the fix time
    plaintext=envelope(0,now-123,payload)
    retired=retired_intent_wire(bob,alice,circle,bytes(range(16,32)),now-1000,now+3600000)
    docs=[('alice_account',alice['wire'],alice['a']),('bob_account',bob['wire'],bob['a']),('snapshot',ss,alice['a']),('manifest',mf,alice['d']),('record',rec,alice['d'])]
    for name,wire,sk in docs:
        parsed=verify(wire,bytes(sk.verify_key)); label=LABELS[parsed['type']]
        # Independent OpenSSL Ed25519 signs identical message and reproduces bytes.
        other=Ed25519PrivateKey.from_private_bytes(bytes(sk))
        assert other.sign(C(label)+parsed['body'])==wire[-64:]
        other.public_key().verify(wire[-64:],C(label)+parsed['body'])
    for who in identities:
        assert X25519PrivateKey.from_private_bytes(who['esk']).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)==who['epk']
    rp=verify(rec,bytes(alice['d'].verify_key))
    opened=sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(rp['ciphertext'],aad,rp['nonce'],key)
    assert opened==plaintext and open_envelope(opened)==(0,now-123,payload); assert parse_location(payload)==(377749000,-1224194000,5000,now-123,0)
    negatives=[]
    def negative(name,wire,pk,expected,action='verify'):
        try:
            if action=='verify': verify(wire,pk)
            elif action in('decrypt','open'):
                p=verify(wire,pk)
                try: pt=sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(p['ciphertext'],C('record-aad')+p['header'],p['nonce'],key)
                except CryptoError: raise Bad('DECRYPT_FAILED')
                if action=='open': open_envelope(pt)
            elif action=='payload': parse_location(wire)
            raise AssertionError(name+' unexpectedly accepted')
        except Bad as exc: assert str(exc)==expected,(name,str(exc),expected)
        negatives.append(dict(name=name,wire=wire.hex(),verification_key=pk.hex() if pk else '',operation=action,expected=expected))
    pk=bytes(alice['d'].verify_key)
    negative('N01_version',b'\x02'+rec[1:],pk,'UNSUPPORTED_VERSION')
    negative('N02_type',rec[:1]+b'\xff'+rec[2:],pk,'UNSUPPORTED_TYPE')
    negative('N03_truncated',rec[:-1],pk,'MALFORMED')
    negative('N04_trailing_byte',rec+b'\0',pk,'MALFORMED')
    negative('N05_reserved_flag',rec[:50]+b'\x08'+rec[51:],pk,'MALFORMED')  # bit 3: bit 2 is the status kind since revision 6
    negative('N06_changed_ciphertext',rec[:79]+bytes([rec[79]^1])+rec[80:],pk,'BAD_SIGNATURE')
    negative('N07_wrong_signer',rec,bytes(bob['d'].verify_key),'BAD_SIGNATURE')
    negative('N08_excessive_length',rec[:75]+U32(4123)+rec[79:],pk,'SIZE_LIMIT')
    negative('N09_epoch_zero',rec[:34]+U32(0)+rec[38:],pk,'MALFORMED')
    negative('N10_duplicate_member',snapshot(alice,circle,2,[alice['iid'],alice['iid']]),bytes(alice['a'].verify_key),'MALFORMED')
    negative('N11_missing_owner',snapshot(alice,circle,2,[bob['iid']]),bytes(alice['a'].verify_key),'MALFORMED')
    wrong=bytearray(rec[:-64]); wrong[79]^=1
    negative('N12_valid_signature_bad_tag',sign(alice['d'],'record-sig',bytes(wrong)),pk,'DECRYPT_FAILED','decrypt')
    # Ed25519 non-canonical scalar S + group order must be rejected.
    L=2**252+27742317777372353535851937790883648493
    noncanonical=rec[:-32]+(int.from_bytes(rec[-32:],'little')+L).to_bytes(32,'little')
    negative('N13_noncanonical_signature',noncanonical,pk,'BAD_SIGNATURE')
    negative('N14_latitude',location(900000001,0,1,now,0),None,'BAD_PAYLOAD','payload')
    negative('N15_payload_trailing',payload+b'\0',None,'BAD_PAYLOAD','payload')
    bad_account=b'\x05\x01'+ID('bad')+bytes(alice['a'].verify_key)+U64(1)+bytes(range(16))+pk+bytes(32)
    negative('N16_low_order_box_key',sign(alice['a'],'account-sig',bad_account),None,'INVALID_KEY')
    negative('N17_oversize_document',bytes(16385),pk,'SIZE_LIMIT')
    negative('N18_bad_account_id',b'\x05\x01\x01!'+alice['wire'][8:],None,'MALFORMED')
    # Authenticate altered time independently, then show AAD mismatch fails AEAD.
    altered=bytearray(rec[:-64]); altered[49]^=1
    negative('N19_header_aad_binding',sign(alice['d'],'record-sig',bytes(altered)),pk,'DECRYPT_FAILED','decrypt')
    negative('N20_retired_type5',retired,bytes(bob['a'].verify_key),'UNSUPPORTED_TYPE')
    negative('N21_reserved_bit0',rec[:50]+b'\x01'+rec[51:],pk,'MALFORMED')
    # Revision 8: both header bits are class 3, which is legal; the envelope version is checked after decryption.
    bad_envelope,_,_=record(alice,1,0,now,0,bytes(range(24)),key,payload,plaintext=b'\x02'+plaintext[1:])
    negative('N22_envelope_version',bad_envelope,pk,'MALFORMED','open')
    kchecks=[]
    def reject_box(name,box,recipient,expected):
        try: sodium.crypto_box_seal_open(box,recipient['epk'],recipient['esk']); raise AssertionError(name)
        except CryptoError: pass
        kchecks.append(dict(name=name,expected=expected))
    reject_box('W01_wrong_recipient',wraps[alice['iid']],bob,'OPEN_FAILED')
    changed=bytearray(wraps[alice['iid']]); changed[-1]^=1
    reject_box('W02_tampered_box',bytes(changed),alice,'OPEN_FAILED')
    assert H(C('epoch-key')+stream_id(alice['iid'],alice['device_id'])+U32(2)+key)!=parse(mf)['commit']
    kchecks.append(dict(name='W03_wrong_epoch_key_commitment',expected='KEY_COMMITMENT_MISMATCH'))
    vectors={
      'profile':'Kavach v1 / protocol revision 4 / SealedStream wire version 5 (labels unchanged)',
      'warning':'All private values here are public TEST FIXTURES. Never use them in production.',
      'inputs':dict(alice_account_seed=bytes(range(32)).hex(),alice_device_seed=bytes(range(32,64)).hex(),bob_account_seed=bytes(range(64,96)).hex(),bob_device_seed=bytes(range(96,128)).hex(),epoch_key=key.hex(),circle_id=circle.hex(),time_ms=now,record_nonce=bytes(range(24)).hex()),
      'identities':[dict(account=p['name'],account_public=bytes(p['a'].verify_key).hex(),device_sign_seed=D(bytes(range(32,64)) if p['name']=='alice' else bytes(range(96,128)),'device-sign').hex(),device_sign_public=bytes(p['d'].verify_key).hex(),device_box_seed=D(bytes(range(32,64)) if p['name']=='alice' else bytes(range(96,128)),'device-box').hex(),device_box_public=p['epk'].hex(),device_box_secret=p['esk'].hex(),identity_id=p['iid'].hex(),device_id=p['device_id'].hex(),generation=p['generation'],certificate_hash=doc_hash(p['wire'][:-64]).hex(),stream_id=stream_id(p['iid'],p['device_id']).hex()) for p in identities],
      'documents':{name:dict(wire=wire.hex(),body_hash=doc_hash(wire[:-64]).hex(),signature=wire[-64:].hex(),verification_key=bytes(sk.verify_key).hex()) for name,wire,sk in docs},
      'wraps':wrap_detail,
      'record':dict(plaintext=plaintext.hex(),envelope='u8(1) || u8(kind) || u64(eventTime or 0) || payload',kind=0,event_time_ms=now-123,header_class=0,payload=payload.hex(),aad=aad.hex(),ciphertext_and_tag=rp['ciphertext'].hex(),record_id=rid.hex(),decoded=dict(latitude_e7=377749000,longitude_e7=-1224194000,accuracy_mm=5000,captured_at_ms=now-123,status=0)),
      'negative_vectors':negatives,'wrap_checks':kchecks,'state_vectors':run_state_tests(),
      'cross_checks':['Ed25519: libsodium signatures exactly equal OpenSSL cryptography signatures for all 5 documents','XChaCha20-Poly1305: libsodium ciphertext/tag exactly equal PyCryptodome','X25519: libsodium public keys exactly equal OpenSSL cryptography public keys','Sealed-box construction: libsodium crypto_box output accepted by libsodium crypto_box_seal_open (same backend, not independent)']}
    # Boundary audience: Alice plus 99 deterministic identities, including a wrap to self.
    group=[alice]+[identity(f'member{i:03d}',H(C('fixture-account')+U32(i)),H(C('fixture-device')+U32(i))) for i in range(1,100)]
    group_wraps={}; group_key=H(C('fixture-group-key'))
    for i,who in enumerate(group):
        verify(who['wire'])
        box,_,_=sealed_fixture(group_key,who,H(C('fixture-ephemeral')+U32(i)))
        group_wraps[who['iid']]=box
    gs=snapshot(alice,circle,2,[x['iid'] for x in group])
    gm=manifest(alice,2,now,group_key,group_wraps,{p['iid']:p for p in group})
    assert len(gs)==3324 and len(gm)==9808 and sum(map(len,group_wraps.values()))==8000
    verify(gs,bytes(alice['a'].verify_key)); verify_manifest_current(gm,alice)
    for recipient in group: assert open_epoch(gm,alice,recipient,group_wraps[recipient['iid']])==group_key
    # Max-size plaintext is an additional independent AEAD comparison.
    max_record,_,_=record(alice,2,0xffffffff,now,1,bytes(range(24,48)),group_key,bytes(4096),kind=1)  # kind 1 with header class 1 and an opaque 4096-byte payload; bit 0 is reserved
    assert len(max_record)==4265
    verify(max_record,pk)
    # A slot-only kind (2, header class 2) with the first profile's 4-byte payload and no event time.
    status_payload=bytes([1,73,0b1001,3])
    status_record,_,status_rid=record(alice,2,7,now,2,bytes(range(48,72)),group_key,status_payload,kind=2)
    assert parse(status_record)['header_class']==2
    verify(status_record,pk)
    vectors['status_record']={'wire':status_record.hex(),'record_id':status_rid.hex(),'epoch_key':group_key.hex(),'payload':status_payload.hex(),'plaintext':envelope(2,None,status_payload).hex(),
        'expected':{'kind':2,'header_class':2,'flags':4,'epoch':2,'counter':7,'event_time_ms':None,'pins':False,'notifies':False}}
    vectors['boundary_100']={
        'seed_rule':'For i=1..99: accountSeed=H(C("fixture-account")||u32(i)); deviceSeed=H(C("fixture-device")||u32(i)); ephemeral seed for all i=0..99: H(C("fixture-ephemeral")||u32(i)). i=0 is Alice. DeviceId=H(C("fixture-device-id")||deviceSeed)[:16]. TEST ONLY.',
        'epoch_key':group_key.hex(),'accounts':[x['wire'].hex() for x in group],
        'snapshot_wire':gs.hex(),'manifest_wire':gm.hex(),
        'wraps':{k.hex():v.hex() for k,v in sorted(group_wraps.items())},
        'expected':{'members':100,'audience':100,'snapshot_bytes':3324,'manifest_bytes':9808,'wrap_bytes':8000},
        'maximum_record_wire':max_record.hex(),'maximum_record_bytes':4265}
    skey=bytes(range(128,160)); snonce=bytes(range(24,48)); dbid=bytes(range(240,256))
    stored_plain=b'{"schema":1,"identityId":"'+alice['iid'].hex().encode()+b'","currentCertificateHash":"'+doc_hash(alice['wire'][:-64]).hex().encode()+b'"}'
    saad=C('storage-aad')+ID('meta')+U32(6)+b'header'+U32(1)+dbid
    sct=sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(stored_plain,saad,snonce,skey)
    independent=ChaCha20_Poly1305.new(key=skey,nonce=snonce); independent.update(saad)
    c,t=independent.encrypt_and_digest(stored_plain); assert c+t==sct
    vectors['storage']={'key':skey.hex(),'nonce':snonce.hex(),'database_instance_id':dbid.hex(),'namespace':'meta','row_key':b'header'.hex(),'plaintext':stored_plain.hex(),'aad':saad.hex(),'value':(snonce+sct).hex()}
    # A new phone keeps Alice's account key and membership; only device keys/stream change.
    new_phone=identity('alice',bytes(range(32)),bytes(range(128,160)),generation=2)
    verify(new_phone['wire']);assert new_phone['iid']==alice['iid']
    assert accept_device_certificate(alice['wire'],new_phone['wire'])=='ACCEPTED'
    impostor=identity('alice',bytes(range(64,96)),bytes(range(128,160)),generation=3)
    conflict=identity('alice',bytes(range(32)),H(C('fixture-conflict')),generation=2)
    device_rejections=[]
    for candidate,expected in [(alice,'DEVICE_ROLLBACK'),(impostor,'ACCOUNT_KEY_CHANGED'),(conflict,'EQUIVOCATION')]:
        try:accept_device_certificate(new_phone['wire'],candidate['wire']);raise AssertionError(expected+' accepted')
        except Bad as exc:assert str(exc)==expected
        device_rejections.append({'wire':candidate['wire'].hex(),'expected':expected})
    assert new_phone['device_id']!=alice['device_id'] and new_phone['epk']!=alice['epk']
    old_members=parse(ss)['members'];assert new_phone['iid'] in old_members
    assert snapshot(new_phone,circle,1,old_members)==ss
    continued=snapshot(new_phone,circle,2,old_members);verify(continued,bytes(alice['a'].verify_key))
    fresh_key=H(C('fixture-after-phone-change'));new_wraps={}
    for i,who in enumerate([new_phone,bob]):
        box,_,_=sealed_fixture(fresh_key,who,H(C('fixture-replacement-wrap')+U32(i)));new_wraps[who['iid']]=box
    new_manifest=manifest(new_phone,1,now+1000,fresh_key,new_wraps,{p['iid']:p for p in [new_phone,bob]})
    new_record,_,_=record(new_phone,1,0,now+1000,0,bytes(range(48,72)),fresh_key,payload)
    assert parse(new_record)['stream']!=parse(rec)['stream']
    try: sodium.crypto_box_seal_open(new_wraps[new_phone['iid']],alice['epk'],alice['esk']);raise AssertionError('old phone opened new wrap')
    except CryptoError: pass
    assert open_epoch(new_manifest,new_phone,new_phone,new_wraps[new_phone['iid']])==fresh_key
    try:verify_manifest_current(mf,new_phone);raise AssertionError('superseded manifest accepted')
    except Bad as exc:assert str(exc)=='SUPERSEDED_DEVICE'
    rk=bytes(range(224,256));vn=bytes(range(72,96))
    vault_wire,vplain,vaad=vault(alice,rk,1,vn,[(circle,alice['iid'],1)])
    restored=open_vault(vault_wire,rk,'alice',bytes(alice['a'].verify_key))
    assert restored[0]==bytes(alice['a']) and restored[3][0][0]==circle
    try:open_vault(vault_wire,bytes(32),'alice',bytes(alice['a'].verify_key));raise AssertionError('wrong recovery code accepted')
    except Bad as exc:assert str(exc)=='DECRYPT_FAILED'
    for wire,sk,label in [(new_phone['wire'],new_phone['a'],'account-sig'),(continued,new_phone['a'],'snapshot-sig'),(new_manifest,new_phone['d'],'epoch-sig'),(new_record,new_phone['d'],'record-sig')]:
        verify(wire,bytes(sk.verify_key));assert Ed25519PrivateKey.from_private_bytes(bytes(sk)).sign(C(label)+wire[:-64])==wire[-64:]
    vectors['phone_replacement']={
        'device_rejections':device_rejections,'new_device_seed':bytes(range(128,160)).hex(),'new_device_id':new_phone['device_id'].hex(),
        'stable_identity_id':new_phone['iid'].hex(),'new_certificate':new_phone['wire'].hex(),
        'same_circle_snapshot':ss.hex(),'next_owner_snapshot':continued.hex(),
        'new_epoch_key':fresh_key.hex(),'new_manifest':new_manifest.hex(),'new_record':new_record.hex(),
        'new_wraps':{i.hex():w.hex() for i,w in new_wraps.items()},
        'checks':['same account identity','same Circle members','same owner key','no owner re-approval','new device stream epoch1/counter0','old phone cannot open new wrap','old author certificate is superseded','new phone can sign next owner snapshot']}
    rcode=recovery_text(rk)
    assert len(rcode)==48 and parse_recovery_text(rcode)==rk
    empty,_,_=vault(alice,rk,2,bytes(range(96,120)),[])
    disabled,_,_=vault(alice,rk,3,bytes(range(120,144)),[(circle,alice['iid'],0)])
    assert open_vault(empty,rk,'alice',bytes(alice['a'].verify_key))[3]==[]
    assert open_vault(disabled,rk,'alice',bytes(alice['a'].verify_key))[3][0][2]==0
    assert len(vault_wire)==43+5+24+4+90+49 and len(empty)==43+5+24+4+90
    vectors['recovery_vault']={'recovery_code':rcode,'empty_vault':empty.hex(),'sharing_disabled_vault':disabled.hex(),'recovery_key':rk.hex(),'nonce':vn.hex(),'plaintext':vplain.hex(),'aad':vaad.hex(),'wire':vault_wire.hex(),'entry_bytes':49,'checks':['account seed recovered','Circle pin and sharing preference recovered','admitted or waiting is read from the current snapshot, not the vault','wrong recovery code rejected']}
    checkin,_,_=record(alice,1,1,now+1,1,bytes(range(144,168)),key,payload,kind=1)
    next_location,_,_=record(alice,1,2,now+2,0,bytes(range(168,192)),key,payload,kind=0,event=now-123)
    archive={};pin=None
    for wire in [rec,checkin,next_location,checkin]:
        q=verify(wire,pk);slot=(q['stream'],q['epoch'],q['counter'])
        h=doc_hash(q['body'])
        if slot in archive:assert archive[slot]==h
        archive[slot]=h
        kind,_,_=open_envelope(sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(q['ciphertext'],C('record-aad')+q['header'],q['nonce'],key))
        if kind==0 and (pin is None or q['counter']>pin):pin=q['counter']
    assert len(archive)==3 and pin==2
    authority=SigningKey(H(C('fixture-reset-authority')));authority_id=bytes(range(16))
    reset_account=identity('alice',H(C('fixture-reset-account')),H(C('fixture-reset-device')))
    rb=b'\x05\x07'+ID('alice')+alice['iid']+reset_account['iid']+bytes(range(16,32))+U64(now+10000)+authority_id
    receipt=sign(authority,'reset-sig',rb)
    parsed=verify(receipt,bytes(authority.verify_key));assert parsed['old']==alice['iid'] and parsed['new']==reset_account['iid']
    assert parsed['authority_id']==authority_id and reset_account['iid'] not in parse(ss)['members']
    try:verify(receipt,bytes(alice['a'].verify_key));raise AssertionError('untrusted reset authority accepted')
    except Bad as e:assert str(e)=='BAD_SIGNATURE'
    retired={parsed['old']};closed={circle} if parse(ss)['owner'] in retired else set()
    assert circle in closed and reset_account['iid'] not in old_members
    for wire,sk,label in [(checkin,alice['d'],'record-sig'),(next_location,alice['d'],'record-sig'),(receipt,authority,'reset-sig')]:
        assert Ed25519PrivateKey.from_private_bytes(bytes(sk)).sign(C(label)+wire[:-64])==wire[-64:]
    vectors['durable_events']={'checkin_wire':checkin.hex(),'following_location_wire':next_location.hex(),'expected_retained_records':3,'expected_latest_location_counter':2,'duplicate_checkin_adds_record':False}
    vectors['account_reset']={'authority_seed':bytes(authority).hex(),'authority_public':bytes(authority.verify_key).hex(),'authority_key_id':authority_id.hex(),'new_account_certificate':reset_account['wire'].hex(),'receipt_wire':receipt.hex(),'expected':['ACCOUNT_KEY_CHANGED','old owner Circle closed by reset receipt','new identity not admitted','wrong authority rejected']}
    # Operational keys can be removed without replacing the pinned management root.
    root=SigningKey(H(C('fixture-management-root')))
    standby=SigningKey(H(C('fixture-reset-standby'))); standby_id=bytes(range(32,48))
    root_pk=bytes(root.verify_key); standby_pk=bytes(standby.verify_key)
    entries=[(authority_id,bytes(authority.verify_key)),(standby_id,standby_pk)]
    kl1=reset_key_list(root,1,now,now+86400000,entries)
    kl2=reset_key_list(root,2,now+20000,now+86400000,entries[1:])
    reissued=sign(standby,'reset-sig',rb[:-16]+standby_id)
    cases=[]
    def case(name,fn,expected):
        try: actual=fn()
        except Bad as e: actual=str(e)
        assert actual==expected,(name,actual,expected)
        cases.append(dict(name=name,expected=expected))
    trust=ResetTrust(root_pk)
    case('K01_initial_list',lambda:trust.install(kl1,now),'INSTALLED')
    case('K02_list_duplicate',lambda:trust.install(kl1,now),'DUPLICATE')
    case('K03_active_reset',lambda:trust.apply(receipt,reset_account['wire'],'alice',alice['iid'],now+10000),'ACCOUNT_KEY_CHANGED')
    case('K04_remove_active_key',lambda:trust.install(kl2,now+20000),'INSTALLED')
    case('K05_list_rollback',lambda:trust.install(kl1,now+20000),'ROLLBACK')
    conflict=reset_key_list(root,2,now+20000,now+86400000,entries)
    case('K06_equal_version_conflict',lambda:trust.install(conflict,now+20000),'EQUIVOCATION')
    unseen=ResetTrust(root_pk); unseen.install(kl2,now+20000)
    case('K07_unseen_backdated_revoked_receipt',lambda:unseen.apply(receipt,reset_account['wire'],'alice',alice['iid'],now+20000),'RESET_KEY_REVOKED')
    case('K08_previously_committed_reset_stays',lambda:trust.apply(receipt,reset_account['wire'],'alice',reset_account['iid'],now+20000),'DUPLICATE')
    case('K09_current_key_reattests_old_event',lambda:unseen.apply(reissued,reset_account['wire'],'alice',alice['iid'],now+20000),'ACCOUNT_KEY_CHANGED')
    case('K10_reattest_applied_event',lambda:trust.apply(reissued,reset_account['wire'],'alice',reset_account['iid'],now+20000),'DUPLICATE')
    fresh=ResetTrust(root_pk); fresh.install(kl2,now+20000)
    case('K11_expired_list_defers_reset',lambda:fresh.apply(reissued,reset_account['wire'],'alice',alice['iid'],now+86400000),'RESET_KEYS_REQUIRED')
    case('K12_unknown_clock',lambda:fresh.apply(reissued,reset_account['wire'],'alice',alice['iid'],None),'RESET_CLOCK_UNTRUSTED')
    case('K13_clock_rollback',lambda:fresh.install(kl2,now+19999),'RESET_CLOCK_UNTRUSTED')
    self_signed=reset_key_list(authority,3,now,now+86400000,entries)
    case('K14_operational_key_cannot_manage',lambda:fresh.install(self_signed,now+20000),'BAD_SIGNATURE')
    case('K15_missing_list',lambda:ResetTrust(root_pk).apply(receipt,reset_account['wire'],'alice',alice['iid'],now),'RESET_KEYS_REQUIRED')
    case('K16_packaged_minimum',lambda:ResetTrust(root_pk,2).install(kl1,now),'ROLLBACK')
    kill=reset_key_list(root,3,now+20000,now+86400000,[])
    case('K17_empty_list',lambda:fresh.install(kill,now+20000),'INSTALLED')
    case('K18_all_resets_disabled',lambda:fresh.apply(reissued,reset_account['wire'],'alice',alice['iid'],now+20000),'RESET_KEY_REVOKED')
    too_long=reset_key_list(root,4,now,now+2592000001,entries)
    case('K19_lifetime_limit',lambda:fresh.install(too_long,now+20000),'MALFORMED')
    duplicate_ids=reset_key_list(root,4,now,now+86400000,[entries[0],entries[0]])
    case('K20_duplicate_keys',lambda:fresh.install(duplicate_ids,now+20000),'MALFORMED')
    root_as_op=reset_key_list(root,4,now,now+86400000,[(authority_id,root_pk)])
    case('K21_root_is_not_operational',lambda:fresh.install(root_as_op,now+20000),'INVALID_KEY')
    conflicting_receipt=sign(standby,'reset-sig',b'\x05\x07'+ID('alice')+bob['iid']+reset_account['iid']+bytes(range(16,32))+U64(now+10000)+standby_id)
    case('K22_reset_id_binding',lambda:trust.apply(conflicting_receipt,reset_account['wire'],'alice',reset_account['iid'],now+20000),'RESET_BINDING')
    assert len(kl1)==187 and len(kl2)==139 and len(kill)==91
    for wire in [kl1,kl2,kill]:
        assert Ed25519PrivateKey.from_private_bytes(bytes(root)).sign(C('reset-keys-sig')+wire[:-64])==wire[-64:]
    vectors['reset_key_management']={
        'management_seed':bytes(root).hex(),'management_public':root_pk.hex(),
        'standby_seed':bytes(standby).hex(),'standby_public':standby_pk.hex(),'standby_id':standby_id.hex(),
        'list_v1_wire':kl1.hex(),'list_v2_wire':kl2.hex(),'empty_list_wire':kill.hex(),
        'reattested_receipt_wire':reissued.hex(),
        'rejected_wires':{'equal_version_conflict':conflict.hex(),'operational_self_signed':self_signed.hex(),'excess_lifetime':too_long.hex(),'duplicate_keys':duplicate_ids.hex(),'root_as_operational':root_as_op.hex(),'reset_binding_conflict':conflicting_receipt.hex()},
        'cases':cases,'expected_sizes':[187,139,91]}
    # Normalize tuples to JSON arrays for stable reload comparison.
    return json.loads(json.dumps(vectors))

def main():
    actual=build(); path=BASE/'vectors.json'
    if '--generate' in sys.argv:
        path.write_text(json.dumps(actual,indent=2)+'\n')
        print('Generated',path)
    else:
        expected=json.loads(path.read_text()); assert actual==expected,'Frozen vectors differ from generated bytes/results'
    print('PASS: 5 core signed documents; 2 core sealed boxes; 100-member boundary fixture; maximum-size record; encrypted storage fixture (informative); 22 negative byte vectors; 3 wrap/key checks; 17 state-model vectors; phone replacement, recovery, durable check-ins and account-reset fixtures; 22 reset-key-management cases (30-day list lifetime); independent primitive cross-checks.')
    print('Coverage limit: reference codec/model only. No mobile SDK, database crash injection, network adapter or security audit is tested here.')

if __name__=='__main__': main()
