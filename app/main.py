import os
import json
import requests
from datetime import datetime
from flask_fontawesome import FontAwesome
from flask import Flask, render_template, request, url_for, send_from_directory, redirect, abort, jsonify, request
from werkzeug.utils import secure_filename
from models.xmlparser import parse_xml_stats, get_scan_data, get_graph_data
from models.scanVul import getVulners
import logging, sys
from libnmap.process import NmapProcess

from time import sleep

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG) # https://stackoverflow.com/questions/6579496/using-print-statements-only-to-debug/6579522#6579522

app = Flask(__name__)
FontAwesome(app)

app.config['UPLOAD_FOLDER'] = 'files'
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024 # 4mb
app.config['FONTAWESOME_STYLES'] = ['all', 'solid', 'brand']
app.config['FONTAWESOME_SERVE_LOCAL'] = False

@app.route('/')
def index():
    files_directory = '/app/files'

    return render_template('index.html')


@app.route('/files', methods=['GET'])
def files():

    files_directory = '/app/files'
    allFiles = os.listdir(files_directory)
    files = [file for file in allFiles if file.endswith('.xml')]
    return jsonify(files)


@app.route('/delete/<filename>', methods=['POST'])
def delete(filename):
    files_directory = '/app/files'
    
    file_path = os.path.join(files_directory, filename)
    
    if os.path.exists(file_path):
        os.remove(file_path)
        return jsonify({"result": "success"})
    else:
        return jsonify({"result": "error", "message": "File not found"}), 404

        
@app.route('/info')
def about():
    nmap_proc = NmapProcess(targets="scanme.nmap.org", options="-sT")
    nmap_proc.run_background()
    while nmap_proc.is_running():
        print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nmap_proc.etc, nmap_proc.progress))
        sleep(2)
    return render_template('info.html')
   
@app.route('/scan/<filename>', methods=['GET', 'POST'])
def scan(filename):
    pathname = os.path.join(app.config['UPLOAD_FOLDER'], filename) 
    if not os.path.exists(pathname):
        abort(404)
        
    hosts = get_scan_data(pathname)
    if not hosts:
        return render_template('index.html', error_message="Unable to retrieve scan data")
        
    stats = parse_xml_stats(pathname)
    network_nodes, network_edges = get_graph_data(hosts)
    return render_template('scan.html', hosts=hosts, stats=stats, filename=filename)




@app.route('/scanv', methods=['POST'])
def scanv():
    if request.method == "POST":
        
        name = request.form.get("name")
        version = request.form.get("version")

        outputList = getVulners(name, version)
        vOutJson = jsonify(data=outputList)
        logging.info("JSON Response x %s", vOutJson)
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
    app.run(host="0.0.0.0", debug = True)