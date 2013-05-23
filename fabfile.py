from fabric.api import run, sudo, cd, prompt, task, settings, abort
from fabtools import require, python, supervisor, deb, system
from fabtools.require import file as require_file
from fabric.contrib import files
from fabric.colors import green, red
from fabric.context_managers import hide
import string
import random

"""
Script to set up a cozy cloud environnement from a fresh system
Validated on a Debian squeeze 64 bits up to date.

Once your system is updated, launch
$ fab -H user@Ip.Ip.Ip.Ip:Port install
to install the full Cozy stack.
"""

# Helpers

def id_generator(size=32, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
    return ''.join(random.choice(chars) for x in range(size))

username = id_generator()
password = id_generator()


def id_generator(size=40, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for x in range(size))

token = id_generator()


def cozydo(cmd):
    """Run a command as a cozy user"""
    sudo(cmd, user="cozy")


def delete_if_exists(filename):
    """Delete given file if it already exists"""
    if files.exists(filename):
        cozydo("rm -rf %s" % filename)


def su_delete(filename):
    '''Delete given file with root permission'''
    sudo("rm -rf %s" % filename)


# Tasks


@task
def install():
    '''
    Install the full cozy stack.
    '''
    install_tools()
    install_node08()
    install_couchdb()
    install_redis()
    install_postfix()
    create_cozy_user()
    config_couchdb()
    install_monitor()
    install_controller()
    install_indexer()
    install_data_system()
    install_home()
    install_proxy()
    install_apps()
    #init_data()
    #init_domain()
    create_cert()
    install_nginx()
    print(green("Cozy installation finished. Now, enjoy !"))


@task
def uninstall_all():
    '''
    Uninstall the whole stack (work in progress)
    '''
    uninstall_cozy()
    uninstall_node08()
    uninstall_couchdb()
    uninstall_redis()
    uninstall_postfix()


@task
def install_dev():
    '''
    Install stuff to prepare a virtual machine dedicated to development.
    '''
    install_tools()
    install_node08()
    install_couchdb()
    install_redis()
    install_postfix()
    create_cozy_user()
    install_monitor()
    install_controller_dev()
    install_indexer()
    install_data_system()
    install_home()
    install_proxy()
    install_apps()
    #init_domain()
    print(green("The Cozy development environment has been installed."))


@task
def install_tools():
    """
    Install build tools
    """
    deb.update_index()
    deb.upgrade()
    require.deb.packages([
        'python',
        'python-setuptools',
        'python-pip',
        'openssl',
        'libssl-dev',
        'libxml2-dev',
        'libxslt1-dev',
        'build-essential',
        'git',
        'sudo',
    ])
    print(green("Tools successfully installed"))


@task
def install_node08():
    """
    Install Node 0.8.9
    """
    require.nodejs.installed_from_source("0.8.9")
    print(green("Node 0.8.9 successfully installed"))


@task
def uninstall_node08():
    """
    Uninstall node 0.8.9
    """

    sudo("npm uninstall npm")
    require_file(url='http://nodejs.org/dist/v0.8.9/node-v0.8.9.tar.gz')
    sudo("tar -xzf node-v0.8.9.tar.gz")
    with cd('node-v0.8.9'):
        sudo('./configure')
        sudo("make uninstall")
        sudo("make distclean")
    su_delete("node-v0.8.9*")
    print(green("Node 0.8.9 successfully uninstalled"))


@task
def install_couchdb():
    """
    Install CouchDB 1.3.0
    """
    packages = [
        'erlang',
        'libicu-dev',
        'libmozjs185-dev',
        'libcurl4-openssl-dev',
        'curl'
    ]

    # Uncomment thess lines when fabtools 0.14.0 will be out.
    #if system.distrib_id() == "Debian" \
    #and system.distrib_release().startswith('6.0'):
    #    packages.append('libmozjs-dev')
    #packages.append('libmozjs-dev')
    #else:
    #packages.append('libmozjs185-dev')
    require.deb.packages(packages)

    require_file(url='http://apache.crihan.fr/dist/couchdb/source/' +
        '1.3.0/apache-couchdb-1.3.0.tar.gz')
    run('tar -xzvf apache-couchdb-1.3.0.tar.gz')
    with cd('apache-couchdb-1.3.0'):
        run('./configure; make')
        sudo('make install')
    run('rm -rf apache-couchdb-1.3.0')
    run('rm -rf apache-couchdb-1.3.0.tar.gz')

    require.users.user("couchdb", home='/usr/local/var/lib/couchdb')
    sudo('chown -R couchdb:couchdb /usr/local/etc/couchdb')
    sudo('chown -R couchdb:couchdb /usr/local/var/lib/couchdb')
    sudo('chown -R couchdb:couchdb /usr/local/var/log/couchdb')
    sudo('chown -R couchdb:couchdb /usr/local/var/run/couchdb')
    sudo('chmod 0770 /usr/local/etc/couchdb')
    sudo('chmod 0770 /usr/local/var/lib/couchdb')
    sudo('chmod 0770 /usr/local/var/log/couchdb')
    sudo('chmod 0770 /usr/local/var/run/couchdb')

    require.supervisor.process('couchdb', user='couchdb',
        command='couchdb', autostart='true',
        environment='HOME=/usr/local/var/lib/couchdb')
    print(green("CouchDB 1.3.0 successfully installed"))

@task
def config_couchdb():
    with hide('running', 'stdout'):
        couch_admin_path = "127.0.0.1:5984/_config/admins/"
        run('curl -X PUT http://%s%s -d \'\"%s\"\'' %
                (couch_admin_path, username, password))
    sudo('mkdir -p /etc/cozy')
    require.files.file(path='/etc/cozy/couchdb.login',
        contents=username + "\n" + password,
        use_sudo=True,
        owner='cozy-data-system',
        mode='700'
    )
    print(green("CouchDB 1.3.0 successfully configured"))

@task
def uninstall_couchdb():
    """
    Install CouchDB 1.3.0
    """
    require_file(url='http://apache.mirrors.multidist.eu/couchdb/' +
        '1.3.0/apache-couchdb-1.3.0.tar.gz')
    run('tar -xzvf apache-couchdb-1.3.0.tar.gz')
    with cd('apache-couchdb-1.3.0'):
        sudo('./configure')
        sudo('make uninstall')
        sudo('make distclean')
    su_delete('/usr/local/share/couchdb')
    su_delete('/usr/local/lib/couchdb')
    su_delete('/usr/local/var/lib/couchdb')
    su_delete('/usr/local/var/log/couchdb')
    su_delete('/usr/local/var/run/couchdb')
    su_delete('/usr/local/share/doc/couchdb')
    su_delete('/usr/local/bin/couchjs')
    su_delete('/usr/local/bin/couchdb')
    su_delete('apache-couchdb-1.3.0')
    su_delete('apache-couchdb-1.3.0.tar.gz')
    su_delete('/etc/supervisor/conf.d/couchdb.conf')
    supervisor.update_config()
    print(green("CouchDB 1.3.0 successfully uninstalled"))


@task
def install_redis():
    """
    Install Redis 2.4.14
    """
    require.redis.installed_from_source('2.6.12')
    require.redis.instance('cozy', '2.6.12')
    print(green("Redis 2.4.14 successfully installed"))


@task
def uninstall_redis():
    '''
    Uninstall Redis 2.4.14
    '''
    su_delete('/var/lib/redis')
    su_delete('/var/db/redis')
    su_delete('/var/log/redis')
    su_delete('/var/run/redis')
    su_delete('/opt/redis-2.4.14')
    su_delete('/etc/redis')
    su_delete('/etc/supervisor/conf.d/redis_cozy.conf')
    supervisor.update_config()
    print(green("Redis 2.4.14 successfully uninstalled"))


@task
def install_postfix():
    """
    Install a postfix instance (required for mail sending).
    """
    #domain = prompt('Enter your domain name:',
    #                default='myinstance.cozycloud.cc')
    require.postfix.server('cozycloud.cc')
    print(green("Postfix successfully installed"))


@task
def uninstall_postfix():
    """
    Uninstall postfix.
    """
    require.deb.uninstall("postfix")
    print(green("Postfix successfully uninstalled"))


@task
def uninstall_cozy():
    """
    Uninstall postfix.
    """
    supervisor.stop_process("cozy-controller")
    supervisor.stop_process("cozy-indexer")
    su_delete("/usr/local/var/cozy-indexer")
    su_delete('/etc/supervisor/conf.d/cozy-controller.conf')
    su_delete('/etc/supervisor/conf.d/cozy-indexer.conf')
    supervisor.update_config()
    print(green("Cozy successfully uninstalled"))


@task
def create_cozy_user():
    """
    Add Cozy user with no home directory.
    """
    require.user("cozy", home=False, create_home=False)
    require.user("cozy-data-system", create_home=True)
    require.user("cozy-home", create_home=True)


@task
def install_monitor():
    """
    Install Coffeescript, Compound and Cozy Monitor.
    """
    require.nodejs.package('coffee-script')
    require.nodejs.package('cozy-monitor')
    require.nodejs.package('compound')
    print(green("Cozy setup and coffee script successfully installed"))

@task
def install_controller():
    """
    Install Cozy Controller Application Manager. Daemonize with supervisor.
    """
    require.nodejs.package('cozy-controller')
    sudo('mkdir -p /etc/cozy')
    sudo('mkdir -p /etc/cozy/pids')
    require.files.file(path='/etc/cozy/controller.token',
        mode='700',
        contents=token,
        use_sudo=True,
        owner='cozy-home'
    )
    path = "/usr/local/lib/node_modules/cozy-controller/bin/cozy-controller"
    require.supervisor.process('cozy-controller',
        command="/usr/bin/pidproxy /etc/cozy/pids/controller.pid " +
            "%s -u --auth --per 755" % path,
        environment='NODE_ENV="production"',
        user='root'
    )
    supervisor.stop_process('cozy-controller')
    ## In case where two cozy-controller are started
    sudo('pkill -9 node')
    supervisor.start_process('cozy-controller')

    print(green("Cozy Controller successfully started"))

@task
def install_controller_dev():
    """
    Install Cozy Controller Application Manager. Daemonize with supervisor.
    """
    require.nodejs.package('cozy-controller')
    require.supervisor.process('cozy-controller',
        command="cozy-controller -c -u --per 755",
        environment='NODE_ENV="development"',
        user='root'
    )
    supervisor.restart_process('cozy-controller')

    print(green("Cozy Controller successfully started"))


@task
def install_indexer():
    """
    Install Cozy Data Indexer. Use supervisord to daemonize it.
    """
    home = "/usr/local/cozy-indexer"
    indexer_dir = "%s/cozy-data-indexer" % home
    indexer_env_dir = "%s/virtualenv" % indexer_dir
    python_exe = indexer_dir + "/virtualenv/bin/python"
    indexer_exe = "server.py"
    process_name = "cozy-indexer"

    require.files.directory(home, use_sudo=True)

    with cd(home):
        delete_if_exists("cozy-data-indexer")
        sudo('git clone git://github.com/mycozycloud/cozy-data-indexer.git')

    require.python.virtualenv(indexer_env_dir, use_sudo=True)
    with python.virtualenv(indexer_env_dir):
        sudo("pip install --use-mirrors -r %s/requirements/common.txt" % \
                indexer_dir)

    sudo("chown -R cozy:cozy %s" % home)

    require.supervisor.process(process_name,
        command='%s %s' % (python_exe, indexer_exe),
        directory=indexer_dir,
        user="cozy"
    )
    supervisor.restart_process(process_name)
    print(green("Data Indexer successfully started"))


@task
def install_data_system():
    """
    Install Cozy Data System. Daemonize with Haibu.
    """
    result = sudo('cozy-monitor install data-system')
    installedApp = result.count("successfully installed")
    if installedApp == 0:
        print(red("Installation of data-system failed.\n" +
            "You can join us on our IRC channel : #cozycloud on freenode.net."))
        exit()
    else:
        print(green("Data-system successfully installed"))

@task
def install_home():
    """
    Install Cozy Home
    """
    sudo('npm install -g brunch')
    result = sudo('cozy-monitor install home')
    installedApp = result.count("successfully installed")
    if installedApp == 0:
        print(red("Installation of home failed.\n" +
            "You can join us on our IRC channel : #cozycloud on freenode.net."))
        exit()
    else:
        print(green("Home successfully installed"))


@task
def install_proxy():
    """
    Install Cozy Proxy
    """
    result = sudo('cozy-monitor install proxy')
    installedApp = result.count("successfully installed")
    if installedApp == 0:
        print(red("Installation of proxy failed.\n" +
            "You can join us on our IRC channel : #cozycloud on freenode.net."))
        exit()
    else:
        print(green("Proxy successfully installed"))

@task
def install_apps():
    """
    Install Cozy Notes and Cozy Todos
    """
    pass
    #sudo('cozy-monitor install_home notes')
    #sudo('cozy-monitor install_home todos')
    #print(green("Apps successfully started"))


@task
def init_data():
    """
    Data initialization
    """
    cozydo('cozy-monitor script notes init')
    cozydo('cozy-monitor script todos init')
    print(green("Data successfully initialized"))


@task
def init_domain():
    """
    Register domain name inside Cozy Home.
    """
    domain = prompt("What is your domain name (ex: cozycloud.cc)?")
    cozydo('cozy-monitor script home setdomain %s' % domain)
    print(green("Domain set to: %s" % domain))


@task
def create_cert():
    """
    Create SSL certificates.
    """

    etc_dir = "/etc/cozy"
    require.files.directory(etc_dir, use_sudo=True, owner="cozy")
    with cd(etc_dir):
        sudo('openssl genrsa -out ./server.key 1024')
        sudo('openssl req -new -x509 -days 3650 -key ' + \
               './server.key -out ./server.crt  -batch')
        sudo('chmod 640 server.key')
        sudo('chown cozy:ssl-cert ./server.key')
    print(green("Certificates successfully created."))


PROXIED_SITE_TEMPLATE = """\
server {
    listen %(port)s;
    server_name %(server_name)s;

    ssl_certificate /etc/cozy/server.crt;
    ssl_certificate_key /etc/cozy/server.key;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout  10m;
    ssl_protocols  SSLv3 TLSv1;
    ssl_ciphers  ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv3:+EXP;
    ssl_prefer_server_ciphers   on;
    ssl on;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";

    gzip_vary on;

    location / {
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_redirect http:// https://;
        proxy_pass %(proxy_url)s;
    }

    access_log /var/log/nginx/%(server_name)s.log;
}
"""

from fabtools.files import is_link
from fabtools.utils import run_as_root
from fabtools.service import reload as reload_service

@task
def site(server_name, template_contents=None, template_source=None,
         enabled=True, check_config=True, **kwargs):

    config_filename = '/etc/nginx/sites-available/%s.conf' % server_name

    context = {
        'port': 80,
    }
    context.update(kwargs)
    context['server_name'] = server_name

    sudo('mkdir -p /etc/nginx')
    sudo('mkdir -p /etc/nginx/sites-available')
    sudo('mkdir -p /etc/nginx/sites-enabled')
    require.files.template_file(config_filename, template_contents, template_source, context, use_sudo=True)

    link_filename = '/etc/nginx/sites-enabled/%s.conf' % server_name
    if enabled:
        if not is_link(link_filename):
            run_as_root("ln -s %(config_filename)s %(link_filename)s" % locals())
        # Make sure we don't break the config
        if check_config:
            with settings(hide('running', 'warnings'), warn_only=True):
                if run_as_root("nginx -t").return_code > 0:
                    run_as_root("rm %(link_filename)s" % locals())
                    message = red("Error in %(server_name)s nginx site config (disabling for safety)" % locals())
                    abort(message)
    else:
        if is_link(link_filename):
            run_as_root("rm %(link_filename)s" % locals())

    run('wget -O init-deb.sh http://library.linode.com/assets/660-init-deb.sh')
    sudo('mv init-deb.sh /etc/init.d/nginx')
    sudo('chmod +x /etc/init.d/nginx')
    sudo('/usr/sbin/update-rc.d -f nginx defaults')
    reload_service('nginx')

@task
def install_nginx():
    """
    Install NGINX and make it use certs.
    """
    require.deb.packages([
        'libpcre3',
        'libpcre3-dev',
        'libssl-dev',
        'build-essential',
        'libgd2-xpm-dev'
    ])
    require_file(url='http://nginx.org/download/nginx-1.4.1.tar.gz')
    run('tar -xzvf nginx-1.4.1.tar.gz')
    with cd('nginx-1.4.1'):
        run('./configure --prefix=/etc/nginx ' +
            '--conf-path=/etc/nginx/nginx.conf ' +
            '--sbin-path=/usr/sbin/nginx ' +
            '--error-log-path=/var/log/nginx/error.log ' +
            '--http-client-body-temp-path=/var/lib/nginx/body ' +
            '--http-fastcgi-temp-path=/var/lib/nginx/fastcgi ' +
            '--http-log-path=/var/log/nginx/access.log ' +
            '--http-proxy-temp-path=/var/lib/nginx/proxy ' +
            '--http-scgi-temp-path=/var/lib/nginx/scgi ' +
            '--http-uwsgi-temp-path=/var/lib/nginx/uwsgi ' +
            '--lock-path=/var/lock/nginx.lock ' +
            '--pid-path=/var/run/nginx.pid ' + 
            '--with-debug --with-http_addition_module ' +
            '--with-http_dav_module ' +
            #'--with-http_geoip_module ' +
            '--with-http_gzip_static_module ' + 
            '--with-http_image_filter_module ' +
            '--with-http_realip_module ' +
            '--with-http_stub_status_module ' +
            '--with-http_ssl_module ' +
            '--with-http_sub_module ' +
            '--with-http_xslt_module ' +
            '--with-ipv6 ' + 
            '--with-sha1=/usr/include/openssl ' +
            '--with-md5=/usr/include/openssl ' +
            '--with-mail ' +
            '--with-mail_ssl_module ' 
            )
        run('make')   
        sudo('make install')
    run('rm -rf nginx-1.4.1')
    run('rm -rf nginx-1.4.1.tar.gz')

    site("cozy",
        template_contents=PROXIED_SITE_TEMPLATE,
        enabled=True,
        port=443,
        proxy_url='http://127.0.0.1:9104'
    )
    print(green("Nginx successfully installed."))

## No setup tasks

@task
def update_stack():
    """
    Update applications
    """
    sudo('cozy-monitor install data-system')
    sudo('cozy-monitor install home')
    sudo('cozy-monitor token')
    sudo('cozy-monitor install proxy')
    print(green("Applications updated successfully."))


@task
def reset_account():
    """
    Delete current user account
    """
    with cd('/home/cozy/cozy-setup'):
        cozydo('cozy-monitor script home cleanuser')
    print(green("Current account deleted."))
