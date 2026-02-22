import json

def export_json(intel, risks, threat_score):

    data = {
        "intel": intel,
        "risks": risks,
        "score": threat_score
    }

    with open("report_output.json", "w") as f:
        json.dump(data, f, indent=4)