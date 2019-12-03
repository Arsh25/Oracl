from flask import Flask, flash, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
from pymongofunct import get_data, insert_data
from parse import pcapwork
import os
import json

CLIENT = 'localhost'
DB = 'oracl'
COLLECTION = 'pcaps'
UPLOAD_FOLDER = os.path.dirname(os.path.abspath(__file__)) + "/../uploads"
ALLOWED_EXTENSIONS = {'pcap'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/search", methods=['GET', 'POST'])
def test():
    if request.method == "POST":
        search_values = {}

        searches = ["t_start", "t_end",
                    "ip_dst", "ip_src",
                    "mac_dst", "mac_src",
                    "port_dst", "port_src",
                    "collection"]

        for each_search in searches:
            try:
                input = request.form[each_search]
                search_values[each_search] = input
            except:
                pass
            
        redirect_string = "?"
        for key in search_values:
            if (search_values[key]):
                redirect_string += key + '=' + search_values[key] + '&'

        return redirect('/getTraffic'+redirect_string)
    return '''
    <!doctype html>
    <title>Oracl</title>
    <h1>Search Options</h1>
    <form role='form' method=post action='/search'>
      <input type='text' name='t_start' class='form-control' id='timestart-box' placeholder='Enter start time...' style='width: 300px;' autofocus>
      <br>
      <input type='text' name='t_end' class='form-control' id='timeend-box' placeholder='Enter end time...' style='width: 300px;' autofocus>
      <br>
      
      <input type='text' name='ip_dst' class='form-control' id='ipdst-box' placeholder='Enter destination ip...' style='width: 300px;' autofocus>
      <br>
      <input type='text' name='ip_src' class='form-control' id='ipsrc-box' placeholder='Enter source ip...' style='width: 300px;' autofocus>
      <br>
      
      <input type='text' name='mac_dst' class='form-control' id='macdst-box' placeholder='Enter destination mac address...' style='width: 300px;' autofocus>
      <br>
      <input type='text' name='mac_src' class='form-control' id='macsrc-box' placeholder='Enter source mac address...' style='width: 300px;' autofocus>
      <br>
      
      <input type='text' name='port_dst' class='form-control' id='dstport-box' placeholder='Enter destination port...' style='width: 300px;' autofocus>
      <br>
      <input type='text' name='port_src' class='form-control' id='srcport-box' placeholder='Enter source port...' style='width: 300px;' autofocus>
      <br>

      <input type='text' name='collection' class='form-control' id='collection-box' placeholder='Enter collection name...' style='width: 300px;' autofocus>
      <br>
      
      <button type='submit' class='btn btn-default'>Submit</button>
    </form>
    '''

@app.route("/getTraffic", methods=['GET', 'POST'])
def get_traffic():
    timestart = request.args.get('t_start')
    timeend = request.args.get('t_end')

    ipdst = request.args.get('ip_dst')
    ipsrc = request.args.get('ip_src')

    macdst = request.args.get('mac_dst')
    macsrc = request.args.get('mac_src')

    dstport = request.args.get('port_dst')
    srcport = request.args.get('port_src')
    collection = request.args.get('collection')
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

    if collection:
        collect = collection
    else:
        collect = COLLECTION

    return_tuple = get_data(CLIENT, DB, collect, query)

    data = return_tuple[1]
    alldata = json.dumps(data)
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
            if not os.path.exists(UPLOAD_FOLDER):
                try:
                    os.mkdir(UPLOAD_FOLDER)
                except OSError as e:
                    pass
                else:
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
    final = pcapwork(UPLOAD_FOLDER + '/'+ filename)
    collection = filename
    return_tuple = insert_data(CLIENT, DB, collection, final)
    if(return_tuple[0]):
        return "Data has been added to the collection " + collection
    else:
        return(return_tuple[1])



@app.route("/getComparisonResults", methods=['GET'])
def get_comparision_results():
    timestart = request.args.get('t_start')
    timeend = request.args.get('t_end')
    ipdst = request.args.get('ip_dst')
    ipsrc = request.args.get('ip_src')

    macdst = request.args.get('mac_dst')
    macsrc = request.args.get('mac_src')

    dstport = request.args.get('port_dst')
    srcport = request.args.get('port_src')
    collection = request.args.get('collection')
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

    if collection:
        collect = collection

    oracltuple = get_data(CLIENT, DB, COLLECTION, query)
    usertuple = get_data(CLIENT, DB, collect, query) 
    oracldata = oracltuple[1]
    userdata = usertuple[1]
    alldata = oracldata
    alldata.append(userdata)
    jalldata = json.dumps(alldata)
    return jalldata

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
