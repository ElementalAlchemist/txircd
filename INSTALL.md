Installation instructions
=========================

The following steps can be done either directly to the system or in a virtualenv. Ensure that you're running txircd in a Python 3 environment. txircd requires at least Python 3.6.

If you're upgrading txircd from 0.4, make sure to run the data_upgrade_from_0.4_py2.py script from setup-utils in the Python 2.7 environment, then upgrade Python and run data_upgrade_from_0.4_py3.py.
We recommend taking a backup of your database file (no need to back up the yaml file unless you can't get your Python 2.7 environment back) before running the Python 3 conversion.
Run these scripts as `python setup-utils/data_upgrade_from_0.4_py#.py` from the base txircd directory.

1. Install dependencies:  
`pip install -r requirements.txt`

2. Make txircd visible to be run by twistd:
`pip install -e .`
This command sets up symlinks to the current directory. You only need to run this once.

3. Copy `txircd-example.yaml` to `txircd.yaml`, and edit the configuration. Do the same for included files in the `conf/` directory.

4. Allow txircd to daemonize:  
`twistd txircd`  
or run it in the foreground:  
`twistd -n txircd`  
(If you're running in a virtualenv, start txircd with the twistd in your virtualenv.)

Docker instructions
-------------------

1. Copy `txircd-example.yaml` to `txircd.yaml`, and edit the configuration. Do the same for included files in the `conf/` directory.

2. Copy `docker-compose-example.yaml` to `docker-compose.yaml` and edit in the config files you created above.

3. Run txircd:  
`docker-compose up -d txircd`

Public images are available at https://hub.docker.com/r/heufneutje/txircd.
