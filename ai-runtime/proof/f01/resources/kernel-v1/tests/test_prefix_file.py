"""Real filesystem counterexamples; no config/reload/VM action."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('prefix_file',Path(__file__).parents[1]/'python/prefix_file.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class PrefixFile(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name).resolve();self.root.chmod(0o755);self.directory=self.root/'kubelet-kubepods-burstable-.slice.d'
        for key,value in [('DIRECTORY',self.directory),('OWNER_UID',os.getuid()),('OWNER_GID',os.getgid())]:
            p=patch.object(m,key,value);p.start();self.addCleanup(p.stop)
        self.records=[]
    def install(self):return m.install_prefix(lambda tag,value:self.records.append((tag,value)))
    def test_exclusive_install_and_exact_owned_remove_preserve_parent(self):
        old=os.umask(0o077)
        try:receipt=self.install()
        finally:os.umask(old)
        self.assertEqual((self.directory/m.FILENAME).read_bytes(),b'[Slice]\nMemorySwapMax=0\n');self.assertEqual((self.directory/m.FILENAME).stat().st_mode&0o777,0o644);self.assertEqual(self.directory.stat().st_mode&0o777,0o755)
        self.assertEqual([row[0] for row in self.records],['directory-created','prefix-file-complete']);self.assertEqual(m.inspect_prefix(receipt),receipt)
        m.remove_prefix(receipt);self.assertFalse(self.directory.exists());self.assertTrue(self.root.is_dir())
    def test_any_existing_directory_file_or_symlink_is_not_adopted(self):
        for kind in ['directory','file','symlink']:
            with self.subTest(kind=kind):
                if kind=='directory':self.directory.mkdir()
                elif kind=='file':self.directory.write_text('foreign')
                else:self.directory.symlink_to(self.root,target_is_directory=True)
                with self.assertRaises((AssertionError,FileExistsError)):self.install()
                if self.directory.is_symlink() or self.directory.is_file():self.directory.unlink()
                else:self.directory.rmdir()
        self.assertEqual(self.records,[])
    def test_parent_symlink_or_writable_parent_refuses_creation(self):
        self.root.chmod(0o777)
        with self.assertRaisesRegex(AssertionError,'^PREFIX_PARENT$'):self.install()
        self.assertFalse(self.directory.exists());self.root.chmod(0o755)
        link=self.root/'link';link.symlink_to(self.root,target_is_directory=True)
        with patch.object(m,'DIRECTORY',link/self.directory.name),self.assertRaisesRegex(AssertionError,'^PREFIX_PARENT$'):self.install()
    def test_changed_content_mode_or_inode_prevents_remove(self):
        receipt=self.install();path=self.directory/m.FILENAME
        for kind in ['content','mode','inode']:
            with self.subTest(kind=kind):
                if kind=='content':path.write_bytes(b'[Slice]\nMemorySwapMax=infinity\n')
                elif kind=='mode':path.chmod(0o666)
                else:
                    path.rename(self.directory/'saved');path.write_bytes(m.CONTENT);(self.directory/'saved').unlink();path.chmod(0o644)
                with self.assertRaises(AssertionError):m.remove_prefix(receipt)
                self.assertTrue(path.exists())
                if kind=='content':path.write_bytes(m.CONTENT)
                if kind=='mode':path.chmod(0o644)
    def test_foreign_extra_member_or_link_prevents_remove(self):
        receipt=self.install();extra=self.directory/'foreign';extra.write_text('x')
        with self.assertRaisesRegex(AssertionError,'^PREFIX_MEMBERSHIP$'):m.remove_prefix(receipt)
        extra.unlink();path=self.directory/m.FILENAME;path.rename(self.directory/'saved');path.symlink_to(self.directory/'saved')
        with self.assertRaises(AssertionError):m.remove_prefix(receipt)
        self.assertTrue(path.is_symlink());self.assertEqual((self.directory/'saved').read_bytes(),m.CONTENT)
    def test_forged_receipt_path_or_identity_never_targets_other_directory(self):
        receipt=self.install()
        for value in [dict(receipt,path='/foreign'),dict(receipt,fileIdentity=[0,1]),dict(receipt,directoryIdentity=[0,1])]:
            with self.assertRaises(AssertionError):m.remove_prefix(value)
        self.assertTrue((self.directory/m.FILENAME).is_file())
    def test_hard_link_or_replaced_directory_refuses_remove(self):
        receipt=self.install();path=self.directory/m.FILENAME;os.link(path,self.root/'alias')
        with self.assertRaises(AssertionError):m.remove_prefix(receipt)
        (self.root/'alias').unlink();self.directory.rename(self.root/'old');self.directory.mkdir();(self.directory/m.FILENAME).write_bytes(m.CONTENT)
        with self.assertRaises(AssertionError):m.remove_prefix(receipt)
        self.assertEqual((self.root/'old'/m.FILENAME).read_bytes(),m.CONTENT)
    def test_evidence_write_failure_stops_without_config_reload_or_guess_cleanup(self):
        def fail(*args):raise OSError('EVIDENCE_FAIL')
        with self.assertRaisesRegex(OSError,'^EVIDENCE_FAIL$'):m.install_prefix(fail)
        self.assertTrue(self.directory.is_dir());self.assertEqual(list(self.directory.iterdir()),[])
if __name__=='__main__':unittest.main()
