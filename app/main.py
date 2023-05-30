import os
import json
import requests
from datetime import datetime
from flask_fontawesome import FontAwesome
from flask import Flask, render_template, request, url_for, send_from_directory, redirect, abort, jsonify, Response
from werkzeug.utils import secure_filename
from models.xmlparser import parse_xml_stats, get_scan_data, get_graph_data
from models.scanVul import getVulners
import logging, sys
from libnmap.process import NmapProcess
from flask_socketio import SocketIO
from time import sleep

logging.basicConfig(stream=sys.stderr, level=logging.info) # https://stackoverflow.com/questions/6579496/using-print-statements-only-to-debug/6579522#6579522

app = Flask(__name__)
FontAwesome(app)

app.config['UPLOAD_FOLDER'] = 'files'
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024 # 4mb
app.config['FONTAWESOME_STYLES'] = ['all', 'solid', 'brand']
app.config['FONTAWESOME_SERVE_LOCAL'] = False

app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, async_mode='gevent_uwsgi', engineio_logger=True)
    
@app.route('/')
def index():
    files_directory = '/app/files'

    return render_template('index.html')


@app.route('/files', methods=['GET'])
def files():

    files_directory = '/app/files'
    allFiles = os.listdir(files_directory)
    files = [file for file in allFiles if file.endswith('.xml')] # Get list of only xml files
    return jsonify(files)


# Concatenates the file path and the filename to create a full path. Deletes if file exists.
@app.route('/delete/<filename>', methods=['POST'])
def delete(filename):
    files_directory = '/app/files'
    file_path = os.path.join(files_directory, filename)

    if os.path.exists(file_path):
        os.remove(file_path)
        return jsonify({"result": "success"})
    else:
        return jsonify({"message": "File not found"})

        
@app.route('/info')
def about():

    return render_template('info.html')

@app.route('/credits')
def authors():

    return render_template('credits.html')
  
@app.route('/scan/<filename>', methods=['GET', 'POST'])
def scan(filename):
    pathname = os.path.join(app.config['UPLOAD_FOLDER'], filename) 
    if not os.path.exists(pathname):
        abort(404)
        
    hosts = get_scan_data(pathname)
    if not hosts:
        return render_template('index.html', error_message="Unable to retrieve scan data")
        
    # Uses the parse_xml_stats function from xmlparser.py to get the scan data in dictionary
    # format and pass it to the scan.html template
    stats = parse_xml_stats(pathname)
    network_nodes, network_edges = get_graph_data(hosts)
    return render_template('scan.html', hosts=hosts, stats=stats, filename=filename)

# Emits a message to the client on connection
@socketio.on('connect')
def test_connect():
    socketio.emit('my response', {'data': 'Connected'})

# Recieves a message sent after connection from the client and prints it to the console.
# For debbuging purposes.
@socketio.on('my event')
def handle_my_custom_event(json):
    print('received json: ' + str(json))


@app.route('/nmapscan', methods=['POST'])
def startnmapproc():
    if request.method == "POST":
        targets = request.form.get("target")
        logging.debug("this is the target received by the server x %s", targets)
        options = request.form.get("options")
        logging.debug("this is the options received by the server x %s", options)
        filename = request.form.get("filename") if request.form.get("filename") else datetime.now().strftime("%Y%m%d%H%M")
        logging.info("this is the filename received by the server x %s", filename)

        # Create a libnmap.process.NmapProcess object and run it in the background
        # while the scan is running, every two seconds emits info to the client
        nmap_proc = NmapProcess(targets=targets, options=options)
        nmap_proc.run_background()
        while nmap_proc.is_running():
            print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nmap_proc.etc, nmap_proc.progress))
            socketio.emit('update output', "Nmap Scan running: Current Task: {0} | DONE: {1}%".format(
                nmap_proc.current_task.name if nmap_proc.current_task else "No task started yet", nmap_proc.progress))
            socketio.sleep(2)

        print("rc: {0} output: {1}".format(nmap_proc.rc, nmap_proc.summary))
        socketio.emit('update output', nmap_proc.summary) # Send the summary to the client

        with open(os.path.join(app.config['UPLOAD_FOLDER'], filename + ".xml") , "w") as f:
            print(nmap_proc.stdout, file=f)
    return jsonify({"result": "success"})

@app.route('/raw/<filename>')
def view_raw(filename):
    files = '/app/files'
    logging.info("There has been a successful request for file %s", filename)
    return send_from_directory(files, filename)

@app.route('/scanv', methods=['POST'])
def scanv():
    if request.method == "POST":
        name = request.form.get("name")
        logging.debug("this is the name received by the server x -%s-", name)
        version = request.form.get("version")
        logging.debug("this is the version received by the server x %s", version)
        
        # Check if product is known, if it is not, return an empty string, it is handled by the client
        # If not, run the getVulners function from scanVul.py
        if(name == " "):
            outputList = ""
            vOutJson = jsonify(data=outputList)
            logging.info("JSON Response, database search bypass due to malformed request x %s", vOutJson)
        else:
            outputList = getVulners(name, version)
            vOutJson = jsonify(data=outputList)
            logging.debug("JSON Response x %s", vOutJson)
        
        # Return the outputList as a JSON response
        return jsonify(outputList)


@app.route('/graph/<filename>')
def browse(filename):
    pathname = os.path.join(app.config['UPLOAD_FOLDER'], filename) 
    if not os.path.exists(pathname):
        abort(404)
    hosts = get_scan_data(pathname)
    if not hosts:
        return render_template('index.html', error_message="Unable to retrieve scan data")
    stats = parse_xml_stats(pathname)
    network_nodes, network_edges = get_graph_data(hosts)
    
    return render_template('graph.html', nodes=json.dumps(network_nodes), edges=json.dumps(network_edges), hosts=hosts, filename=filename)

@app.route("/upload", methods=['POST'])
def upload():
    if 'file' not in request.files:
        return render_template('index.html', error_message="'file' parameter not passed to file uploader.")

    file = request.files['file']
    if file.filename == '':
        return render_template('index.html', error_message="No File Selected.")
    filename=secure_filename(file.filename)

    if file:
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    else:
        return render_template('index.html', error_message="Incorrect file type or empty file.")

    return redirect(url_for("scan", filename=filename))

@app.errorhandler(404)
def page_not_found(error):
   return render_template('404.html'), 404

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0')