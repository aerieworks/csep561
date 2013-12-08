import json
from os import path

from pox.core import core
from pox.lib.revent import EventMixin
from pox.lib.util import dpid_to_str

from device.learning_switch import LearningSwitch
from device.nat import NatRouter


ARG_CONFIG_FILENAME = 'config'

CONFIG_KEY_BRIDGE = 'bridge'
CONFIG_KEY_NAT = 'nat'
CONFIG_KEY_SWITCH = 'switch'


class ControllerManager(EventMixin):

  logger = core.getLogger()

  def __init__(self, config):
    self._switches = []
    self._config = config
    self.listenTo(core)
    self.listenTo(core.openflow)


  """
  Creates a switch instance to manage the new switch connection.
  """
  def _handle_ConnectionUp(self, event):
    switch_name = dpid_to_str(event.dpid)
    if event.dpid == self._config[CONFIG_KEY_SWITCH]:
      ControllerManager.logger.info('Handling switch {} as a NAT router.'.format(switch_name))
      self._switches.append(NatRouter(event, self._config))
    else:
      ControllerManager.logger.info('Handling switch {} as a learning switch.'.format(switch_name))
      self._switches.append(LearningSwitch(event))


"""
Invoked by POX when NatAppliance is specified as a module on the command line:
  $ ./pox csep561.appliance.nat
"""
def launch(**params):
  config_filename = params.get(ARG_CONFIG_FILENAME)
  if config_filename is None:
    raise Exception('You must specify the config file location via the --config parameter.')
  if (not path.isfile(config_filename)):
    raise Exception('The specified config file does not exist.')

  with open(config_filename, 'r') as config_file:
    content = config_file.read()
    print content
    config = json.loads(content)

  core.register('nat_project', ControllerManager(config))

