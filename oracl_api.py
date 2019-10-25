from flask import Flask

app = Flask(__name__)

@app.route("/getTraffic", methods=['GET'])
def get_traffic():
    return 200

@app.route("/postPcap", methods=['POST'])
def post_pcap():
    return 200

@app.route("/getComparisonResults", methods=['GET'])
def get_comparision_results():
    return 200

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
