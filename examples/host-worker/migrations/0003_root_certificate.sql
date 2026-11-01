-- Revision 9: each succession keeps the certificate it replaced, so the chain's first link names a certificate under the root key.
ALTER TABLE successions ADD COLUMN previous_certificate TEXT;
