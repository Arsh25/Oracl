from flask import Flask, flash, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
from pymongofunct import get_data, insert_data
from parse import pcapwork
import os
import json

UPLOAD_FOLDER = os.path.dirname(os.path.abspath(__file__)) + "/../uploads"
ALLOWED_EXTENSIONS = {'pcap'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/getTraffic", methods=['GET'])
def get_traffic():
    timestart = request.args.get('t_start')
    timeend = request.args.get('t_end')

    ipdst = request.args.get('ip_dst')
    ipsrc = request.args.get('ip_src')

    macdst = request.args.get('mac_dst')
    macsrc = request.args.get('mac_src')

    dstport = request.args.get('port_dst')
    srcport = request.args.get('port_src')

    pagenum = request.args.get('page-no')

    query = {}
    if timestart or timeend:
        query['time_epoc'] = {}
        if timestart:
            timestart = float(timestart)
            query['time_epoc']['$gte'] = timestart
        if timeend:
            timeend = float(timeend)
            query['time_epoc']['$lte'] = timeend

    if ipdst:
        query['data.ipv4dst'] = ipdst

    if ipsrc:
        query['data.ipv4src'] = ipsrc

    if macdst:
        query['data.macdst'] = macdst

    if macsrc:
        query['data.macsrc'] = macsrc

    if dstport:
        dstport = int(dstport)
        query['data.tcpdstport'] = dstport

    if srcport:
        srcport = int(srcport)
        query['data.tcpsrcport'] = srcport

    client = 'localhost'
    db = 'oracl'
    collection = 'pcaps'
    return_tuple = get_data(client, db, collection, query)

    data = return_tuple[1]
    alldata = {}
    for i in range(len(data)):
        alldata[i] = data[i]
    return alldata
    #return request.query_string

@app.route("/postPcap", methods=['POST','GET'])
def post_pcap():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No File Part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No Selected File')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('uploaded_file', filename=filename))
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    final = pcapwork(filename)
    client = 'localhost'
    db = 'oracl'
    collection = str(filename)
    return_tuple = insert_data(client, db, collection, final)
    
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)

@app.route("/getComparisonResults", methods=['GET'])
def get_comparision_results():
    return 200

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
