from flask import Flask, render_template, request, redirect, session, url_for, jsonify
import docker
import sqlite3
import os
import socket
import threading
import time
from datetime import datetime, timedelta


app = Flask(__name__)
app.secret_key = "supersecretkey"
client = docker.from_env()

# Initialize DB
if not os.path.exists("users.db"):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            user_index INTEGER UNIQUE
        )
    """)
    # admin a l’index 0
    c.execute("INSERT INTO users (username, password, is_admin, user_index) VALUES (?, ?, ?, ?)", 
              ("admin", "admin", 1, 0))
    conn.commit()
    conn.close()

SERVICES = {
    "code-server": {
        "image": "codercom/code-server-2",
        "port_base": 10000,
        "env": {"PASSWORD": "studentpass"},
        "volume_path": "/home/coder/project",
        "port_internal": 8443
    },
    "gns3": {
        "image": "takfa19/gns3-server-2",
        "port_base": 11000,
        "env": {},
        "volume_path": "/data",
        "port_internal": 3080
    }
}

def get_user_index(username):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT user_index FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None


def get_user(username):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT username, password, is_admin FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    return row if row else None


def get_all_users():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE is_admin=0")
    users = [row[0] for row in c.fetchall()]
    conn.close()
    return users


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username)
        if user and user[1] == password:
            session['user'] = username
            session['admin'] = user[2]
            return redirect('/dashboard')
    return render_template('login.html')
    
#verifie si le port est dispo pour lancer un nouveau contenneur
def is_port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('0.0.0.0', port)) != 0

@app.route("/api/service-status")
def service_status():
    # Simulé, à remplacer par ta logique réelle
    return jsonify({
        "Jupyter": "Running",
        "VSCode": "Stopped",
        "Terminal": "Running"
    })

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/')
    if session.get('admin'):
        return render_template('admin_dashboard.html', users=get_all_users(), services=list(SERVICES.keys()))
    return render_template('student_dashboard.html', user=session['user'], services=list(SERVICES.keys()))


@app.route('/create_user', methods=['POST'])
def create_user():
    if not session.get('admin'):
        return redirect('/')
    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT MAX(user_index) FROM users")
    result = c.fetchone()
    next_index = (result[0] or 0) + 1  # Si aucun user, on démarre à 1

    try:
        c.execute("INSERT INTO users (username, password, user_index) VALUES (?, ?, ?)", 
                  (username, password, next_index))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()
    return redirect('/dashboard')


@app.route('/launch/<service_name>')
def launch_service(service_name):
    if 'user' not in session:
        return redirect('/')
    user = session['user']
    service = SERVICES.get(service_name)
    if not service:
        return f"Unknown service: {service_name}", 404

    user_index = get_user_index(user)
    if user_index is None:
        return "User index not found", 500

    now_str = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    server_ip = request.host.split(":")[0]  # récupère l'IP du serveur (ex: 192.168.1.10)
    port = service['port_base'] + user_index
    service_url = f"http://{server_ip}:{port}"
    container_name = f"{service_name}-{user}"
    port = service['port_base'] + user_index
    if not is_port_free(port):
        return f"Port {port} is already in use. Please try again later.", 500

    volume_name = f"vol-{service_name}-{user}"
    network_name = f"net-{service_name}"
    

    # Create Docker network if not exists
    try:
        client.networks.get(network_name)
    except docker.errors.NotFound:
        client.networks.create(network_name, driver="bridge")

    # Remove old container if exists
    try:
        old = client.containers.get(container_name)
        old.remove(force=True)
    except:
        pass

    # Create volume if not exists
    try:
        client.volumes.get(volume_name)
    except:
        client.volumes.create(name=volume_name)

    container = client.containers.run(
        service['image'],
        name=container_name,
        detach=True,
        ports={f"{service['port_internal']}/tcp": port},
        environment=service['env'],
        volumes={volume_name: {'bind': service['volume_path'], 'mode': 'rw'}},
#        hostname=hostname,
        network=network_name,
        restart_policy={"Name": "no"},
        labels={"last_access": now_str})
        
    return render_template('service_ready.html', service_name=service_name, service_url=service_url)
    
@app.route('/admin/delete_session/<username>')
def delete_session(username):
    if not session.get('admin'):
        return redirect('/')
    for container in client.containers.list(all=True):
        if container.name.endswith(f"-{username}"):
            container.remove(force=True)
    
    return redirect('/dashboard')


@app.route('/admin/status/<username>')
def check_status(username):
    if not session.get('admin'):
        return redirect('/')
    user_containers = [c.name for c in client.containers.list() if c.name.endswith(f"-{username}")]
    return {"running_containers": user_containers}


@app.route('/admin/install_package', methods=['POST'])
def install_package():
    if not session.get('admin'):
        return redirect('/')
    container_name = request.form['container']
    package_name = request.form['package']
    try:
        container = client.containers.get(container_name)
        exec_log = container.exec_run(f"apt update && apt install -y {package_name}", user="root")
        return exec_log.output.decode()
    except Exception as e:
        return str(e)


@app.route('/admin/add_service', methods=['POST'])
def add_service():
    if not session.get('admin'):
        return redirect('/')
    name = request.form['name']
    image = request.form['image']
    port_internal = int(request.form['port_internal'])
    port_base = int(request.form['port_base'])
    volume_path = request.form['volume_path']
    SERVICES[name] = {
        "image": image,
        "port_base": port_base,
        "env": {},
        "volume_path": volume_path,
        "port_internal": port_internal
    }
    return redirect('/dashboard')


@app.route('/admin/stop_container', methods=['POST'])
def stop_container():
    if not session.get('admin'):
        return redirect('/')
    name = request.form['container']
    try:
        container = client.containers.get(name)
        container.stop()
        return "Stopped"
    except Exception as e:
        return str(e)


@app.route('/admin/restart_container', methods=['POST'])
def restart_container():
    if not session.get('admin'):
        return redirect('/')
    name = request.form['container']
    try:
        container = client.containers.get(name)
        container.restart()
        return "Restarted"
    except Exception as e:
        return str(e)


@app.route('/admin/logs_container', methods=['POST'])
def logs_container():
    if not session.get('admin'):
        return redirect('/')
    name = request.form['container']
    try:
        container = client.containers.get(name)
        return container.logs().decode()
    except Exception as e:
        return str(e)


@app.route('/logout')
def logout():
    user = session.get('user')

    if user:
        # Supprimer tous les conteneurs de ce user
        for container in client.containers.list(all=True):
            if container.name.endswith(f"-{user}"):
                try:
                    container.remove(force=True)
                except:
                    pass
    session.clear()
    return redirect('/')
    
#supprime les conteneurs qui ont plus de 3 heures
def cleanup_old_containers():
    while True:
        for container in client.containers.list(all=True):
            try:
                labels = container.labels
                last_access = labels.get("last_access")
                if last_access:
                    last_dt = datetime.strptime(last_access, "%Y-%m-%dT%H:%M:%S")
                    if datetime.utcnow() - last_dt > timedelta(hours=0.02):
                        container.remove(force=True)
                        print(f"Container {container.name} removed due to inactivity.")
            except Exception as e:
                print(f"Error while checking container {container.name}: {e}")
        time.sleep(600)  # Attendre 10 minutes avant de rechecker


if __name__ == '__main__':
    threading.Thread(target=cleanup_old_containers, daemon=True).start()

    app.run(debug=True, port=5000)
