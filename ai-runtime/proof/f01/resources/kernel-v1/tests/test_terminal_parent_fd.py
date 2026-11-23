"""Real temp FDs with explicit Linux ACL-list boundary; no cgroup enforcement proof."""
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import test_kernel_measurement as measured

m=measured.m


class TerminalFd(unittest.TestCase):
    def tree(self,root):
        ancestor=root/'ancestor';parent=ancestor/'pod';scope=parent/'scope'
        scope.mkdir(parents=True,mode=0o700)
        values={'pids.max':'256','pids.current':'7','pids.events':'max 0','pids.events.local':'max 0',
            'memory.max':'268435456','memory.current':'1048576','memory.peak':'2097152','memory.swap.max':'0',
            'memory.events':'max 0\noom 0\noom_kill 0','cpu.max':'50000 100000',
            'cpu.stat':'usage_usec 1\nnr_throttled 0','cgroup.stat':'nr_descendants 1\nnr_dying_descendants 0',
            'cgroup.type':'domain'}
        for directory,content in [(parent,values),(scope,{'pids.max':'max','pids.events':'max 0',
                'pids.events.local':'max 0','memory.max':'max','cgroup.type':'domain',
                'cgroup.stat':'nr_descendants 0\nnr_dying_descendants 0'}),(ancestor,{'pids.max':'1000'})]:
            directory.chmod(0o700)
            for name,text in content.items():
                path=directory/name;path.write_bytes((text+'\n').encode());path.chmod(0o600)
        return parent,scope

    def test_child_directory_removal_keeps_new_parent_reader_owned_and_old_live_reader_strict(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(m,'KERNEL_OWNER_UID',os.getuid()), \
             patch.object(m.os,'listxattr',return_value=[],create=True):
            root=Path(directory).resolve();parent,scope=self.tree(root)
            with m.PodCgroup(parent) as held:
                value=m.KernelMeasurement(held,['/ancestor/pod/scope']*3,[None,None],root)
                reader=getattr(value,'read_terminal_parent',None)
                self.assertIsNotNone(reader,'distinct parent reader missing')
                baseline=value.read()
                for path in scope.iterdir():path.unlink()
                scope.rmdir();(parent/'cgroup.stat').write_bytes(b'nr_descendants 0\nnr_dying_descendants 0\n')
                with self.assertRaisesRegex(m.ProofError,'SEED_SCOPE'):value.read()
                terminal=reader()
                self.assertEqual(terminal['parentOrigin'],[str(parent),held.identity])
                self.assertEqual(terminal['counters'],baseline['counters'])

    def test_same_bytes_under_replaced_path_cannot_rebind_the_held_original_directory(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(m,'KERNEL_OWNER_UID',os.getuid()), \
             patch.object(m.os,'listxattr',return_value=[],create=True):
            root=Path(directory).resolve();parent,_=self.tree(root)
            with m.PodCgroup(parent) as held:
                value=m.KernelMeasurement(held,['/ancestor/pod/scope']*3,[None,None],root)
                reader=getattr(value,'read_terminal_parent',None)
                self.assertIsNotNone(reader,'distinct parent reader missing')
                value.read();old=parent.with_name('held-original');parent.rename(old)
                shutil.copytree(old,parent)
                with self.assertRaisesRegex(m.ProofError,'CGROUP_IDENTITY'):reader()
                with self.assertRaisesRegex(m.ProofError,'CGROUP_IDENTITY'):held.check_retained()

    def test_removed_parent_keeps_only_existing_captured_fd_custody_not_permission_or_closed_fd_credit(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(m,'KERNEL_OWNER_UID',os.getuid()), \
             patch.object(m.os,'listxattr',return_value=[],create=True):
            root=Path(directory).resolve();parent,_=self.tree(root)
            held=m.PodCgroup(parent);self.addCleanup(held.close)
            value=m.KernelMeasurement(held,['/ancestor/pod/scope']*3,[None,None],root)
            value.read();value.read_terminal_parent()
            shutil.rmtree(parent)
            held.check_retained()
            with patch.object(Path,'lstat',side_effect=PermissionError('denied')),self.assertRaises(m.ProofError):
                held.check_retained()
            held.close()
            with self.assertRaises(m.ProofError):held.check_retained()


if __name__=='__main__':unittest.main()
