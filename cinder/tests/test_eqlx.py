import mox
import paramiko
import time

from cinder import context
from cinder import exception
from cinder import flags
from cinder.openstack.common import log as logging
from cinder import test
from cinder.volume import configuration as conf
from cinder.volume.drivers import eqlx

LOG = logging.getLogger(__name__)
FLAGS = flags.FLAGS


class DellEQLSanISCSIDriverTestCase(test.TestCase):

    def setUp(self):
        super(DellEQLSanISCSIDriverTestCase, self).setUp()
        configuration = mox.MockObject(conf.Configuration)
        configuration.san_is_local = False
        configuration.san_ip = "10.0.0.1"
        configuration.san_login = "foo"
        configuration.san_password = "bar"
        configuration.san_ssh_port = 16022
        configuration.san_thin_provision = True
        configuration.append_config_values(mox.IgnoreArg())
        FLAGS.eqlx_pool = 'non-default'
        FLAGS.eqlx_use_chap = True
        FLAGS.eqlx_verbose_ssh = True
        self._context = context.get_admin_context()
        self.driver = eqlx.DellEQLSanISCSIDriver(configuration=configuration)
        self.volume_name = "fakevolume"
        self.connector = {'ip': '10.0.0.2',
                          'initiator': 'iqn.1993-08.org.debian:01:222',
                          'host': 'fakehost'}
        self.fake_iqn = 'iqn.2003-10.com.equallogic:group01:25366:fakev'
        self.driver._group_ip = '10.0.1.6'
        self.properties = {
            'target_discoverd': True,
            'target_portal': '%s:3260' % self.driver._group_ip,
            'target_iqn': self.fake_iqn,
            'volume_id': 1}
        self._model_update = {
            'provider_location': "%s:3260,1 %s 0" % (self.driver._group_ip,
                                                     self.fake_iqn),
            'provider_auth': 'CHAP %s %s' % (FLAGS.eqlx_chap_login,
                                             FLAGS.eqlx_chap_password)
        }

    def _fake_get_iscsi_properties(self, volume):
        return self.properties

    def test_create_volume(self):
        self.driver._execute = self.mox.CreateMock(self.driver._execute)
        volume = {'name': self.volume_name, 'size': 1}
        self.driver._execute('volume', 'create', volume['name'],
                             "%sG" % (volume['size']), 'pool',
                             FLAGS.eqlx_pool, 'thin-provision').\
            AndReturn(['iSCSI target name is %s.' % self.fake_iqn])
        self.mox.ReplayAll()
        model_update = self.driver.create_volume(volume)
        self.assertEqual(model_update, self._model_update)

    def test_delete_volume(self):
        self.driver._execute = self.mox.CreateMock(self.driver._execute)
        volume = {'name': self.volume_name, 'size': 1}
        self.driver._execute('volume', 'select', volume['name'], 'offline')
        self.driver._execute('volume', 'delete', volume['name'])
        self.mox.ReplayAll()
        self.driver.delete_volume(volume)

    def test_create_snapshot(self):
        self.driver._execute = self.mox.CreateMock(self.driver._execute)
        snapshot = {'name': 'fakesnap', 'volume_name': 'fakevolume_name'}
        snap_name = 'fake_snap_name'
        self.driver._execute('volume', 'select', snapshot['volume_name'],
                             'snapshot', 'create-now').\
            AndReturn(['Snapshot name is %s' % snap_name])
        self.driver._execute('volume', 'select', snapshot['volume_name'],
                             'snapshot', 'rename', snap_name,
                             snapshot['name'])
        self.mox.ReplayAll()
        self.driver.create_snapshot(snapshot)

    def test_create_volume_from_snapshot(self):
        self.driver._execute = self.mox.CreateMock(self.driver._execute)
        snapshot = {'name': 'fakesnap', 'volume_name': 'fakevolume_name'}
        volume = {'name': self.volume_name}
        self.driver._execute('volume', 'select', snapshot['volume_name'],
                             'snapshot', 'select', snapshot['name'], 'clone',
                             volume['name']).\
            AndReturn(['iSCSI target name is %s.' % self.fake_iqn])
        self.mox.ReplayAll()
        model_update = self.driver.create_volume_from_snapshot(volume,
                                                               snapshot)
        self.assertEqual(model_update, self._model_update)

    def test_create_cloned_volume(self):
        self.driver._execute = self.mox.CreateMock(self.driver._execute)
        src_vref = {'id': 'fake_uuid'}
        volume = {'name': self.volume_name}
        src_volume_name = FLAGS.volume_name_template % src_vref['id']
        self.driver._execute('volume', 'select', src_volume_name, 'clone',
                             volume['name']).\
            AndReturn(['iSCSI target name is %s.' % self.fake_iqn])
        self.mox.ReplayAll()
        model_update = self.driver.create_cloned_volume(volume, src_vref)
        self.assertEqual(model_update, self._model_update)

    def test_delete_snapshot(self):
        self.driver._execute = self.mox.CreateMock(self.driver._execute)
        snapshot = {'name': 'fakesnap', 'volume_name': 'fakevolume_name'}
        self.driver._execute('volume', 'select', snapshot['volume_name'],
                             'snapshot', 'delete', snapshot['name'])
        self.mox.ReplayAll()
        self.driver.delete_snapshot(snapshot)

    def test_initialize_connection(self):
        self.driver._execute = self.mox.CreateMock(self.driver._execute)
        volume = {'name': self.volume_name}
        self.stubs.Set(self.driver, "_get_iscsi_properties",
                       self._fake_get_iscsi_properties)
        self.driver._execute('volume', 'select', volume['name'], 'access',
                             'create', 'initiator',
                             self.connector['initiator'], 'authmethod chap',
                             'username', FLAGS.eqlx_chap_login)
        self.mox.ReplayAll()
        iscsi_properties = self.driver.initialize_connection(volume,
                                                             self.connector)
        self.assertEqual(iscsi_properties['data'],
                         self._fake_get_iscsi_properties(volume))

    def test_terminate_connection(self):
        self.driver._execute = self.mox.CreateMock(self.driver._execute)
        volume = {'name': self.volume_name}
        self.driver._execute('volume', 'select', volume['name'], 'access',
                             'delete', '1')
        self.mox.ReplayAll()
        self.driver.terminate_connection(volume, self.connector)

    def test_do_setup(self):
        self.driver._execute = self.mox.CreateMock(self.driver._execute)
        fake_group_ip = '10.1.2.3'
        for feature in ('confirmation', 'paging', 'events', 'formatoutput'):
            self.driver._execute('cli-settings', feature, 'off')
        self.driver._execute('grpparams', 'show').\
            AndReturn(['Group-Ipaddress: %s' % fake_group_ip])
        self.mox.ReplayAll()
        self.driver.do_setup(self._context)
        self.assertEqual(fake_group_ip, self.driver._group_ip)

    def test_update_volume_status(self):
        self.driver._execute = self.mox.CreateMock(self.driver._execute)
        self.driver._execute('pool', 'select', flags.FLAGS.eqlx_pool, 'show').\
            AndReturn(['TotalCapacity: 111GB', 'FreeSpace: 11GB'])
        self.mox.ReplayAll()
        self.driver._update_volume_status()
        self.assertEqual(self.driver._stats['total_capacity_gb'], 111.0)
        self.assertEqual(self.driver._stats['free_capacity_gb'], 11.0)

    def test_get_space_in_gb(self):
        self.assertEqual(self.driver._get_space_in_gb('123.0GB'), 123.0)
        self.assertEqual(self.driver._get_space_in_gb('123.0TB'), 123.0 * 1024)
        self.assertEqual(self.driver._get_space_in_gb('1024.0MB'), 1.0)

    def test_get_output(self):

        def _fake_recv(ignore_arg):
            return '%s> ' % FLAGS.eqlx_group_name

        chan = self.mox.CreateMock(paramiko.Channel)
        self.stubs.Set(chan, "recv", _fake_recv)
        self.assertEqual(self.driver._get_output(chan), [_fake_recv(None)])

    def test_get_prefixed_value(self):
        lines = ['Line1 passed', 'Line1 failed']
        prefix = ['Line1', 'Line2']
        expected_output = [' passed', None]
        self.assertEqual(self.driver._get_prefixed_value(lines, prefix[0]),
                         expected_output[0])
        self.assertEqual(self.driver._get_prefixed_value(lines, prefix[1]),
                         expected_output[1])

    def test_run_ssh(self):
        chan = self.mox.CreateMock(paramiko.Channel)
        self.driver.ssh = mox.MockAnything()
        self.mox.StubOutWithMock(self.driver.ssh, 'open_session')
        self.mox.StubOutWithMock(self.driver, '_get_output')
        self.mox.StubOutWithMock(chan, 'invoke_shell')
        expected_output = ['NoError: test run']
        self.driver.ssh.open_session().AndReturn(chan)
        chan.invoke_shell()
        self.driver._get_output(chan).AndReturn(expected_output)
        cmd = 'this is dummy command'
        chan.send('stty columns 255' + '\r')
        self.driver._get_output(chan).AndReturn(expected_output)
        chan.send(cmd + '\r')
        self.driver._get_output(chan).AndReturn(expected_output)
        chan.close()
        self.mox.ReplayAll()
        self.assertEqual(self.driver._run_ssh(cmd), expected_output)

    def test_run_ssh_error(self):
        chan = self.mox.CreateMock(paramiko.Channel)
        self.driver.ssh = mox.MockAnything()
        self.mox.StubOutWithMock(self.driver.ssh, 'open_session')
        self.mox.StubOutWithMock(self.driver, '_get_output')
        self.mox.StubOutWithMock(chan, 'invoke_shell')
        expected_output = ['Error: test run', '% Error']
        self.driver.ssh.open_session().AndReturn(chan)
        chan.invoke_shell()
        self.driver._get_output(chan).AndReturn(expected_output)
        cmd = 'this is dummy command'
        chan.send('stty columns 255' + '\r')
        self.driver._get_output(chan).AndReturn(expected_output)
        chan.send(cmd + '\r')
        self.driver._get_output(chan).AndReturn(expected_output)
        chan.close()
        self.mox.ReplayAll()
        self.assertRaises(exception.ProcessExecutionError,
                          self.driver._run_ssh, cmd)

    def test_with_timeout(self):
        @eqlx.with_timeout
        def no_timeout(cmd):
            return 'no timeout'

        @eqlx.with_timeout
        def w_timeout(cmd):
            time.sleep(1)

        self.assertEqual(no_timeout('fake cmd'), 'no timeout')
        self.assertRaises(eqlx.Timeout, w_timeout, 'fake cmd', timeout=0.1)

    def test_execute(self):
        self.mox.StubOutWithMock(self.driver, '_check_connection')
        self.mox.StubOutWithMock(self.driver, '_run_ssh')
        cmd = ('fake', 'cmd')
        self.driver._check_connection()
        self.driver._run_ssh(' '.join(cmd), timeout=FLAGS.eqlx_cli_timeout).\
            AndRaise(eqlx.Timeout())
        self.mox.ReplayAll()
        self.assertRaises(exception.Error, self.driver._execute, *cmd)
        self.mox.ResetAll()
        expected_output = 'fake output'
        self.driver._check_connection()
        self.driver._run_ssh(' '.join(cmd), timeout=FLAGS.eqlx_cli_timeout).\
            AndReturn(expected_output)
        self.mox.ReplayAll()
        self.assertEqual(expected_output, self.driver._execute(*cmd))

    def test_check_connection(self):
        FLAGS.eqlx_cli_retries_timeout = 0.1
        FLAGS.eqlx_cli_max_retries = 2
        self.mox.StubOutWithMock(self.driver, '_run_ssh')
        self.mox.StubOutWithMock(self.driver, '_connect_to_ssh')
        self.driver._connect_to_ssh().AndReturn('fake_ssh')
        self.mox.ReplayAll()
        self.driver._check_connection()
        self.assertEqual('fake_ssh', self.driver.ssh)
        self.mox.ResetAll()
        self.driver._run_ssh('cli-settings', 'show',
                             timeout=FLAGS.eqlx_cli_timeout).\
            AndRaise(eqlx.Timeout())
        self.driver._connect_to_ssh().AndRaise(eqlx.Timeout())
        self.mox.ReplayAll()
        self.assertRaises(exception.Error, self.driver._check_connection)
        self.mox.ResetAll()
        self.driver.ssh = 'fake_ssh'
        self.driver._run_ssh('cli-settings', 'show',
                             timeout=FLAGS.eqlx_cli_timeout)
        self.mox.ReplayAll()
        self.driver._check_connection()

    def test_local_path(self):
        self.assertRaises(NotImplementedError, self.driver.local_path, '')
