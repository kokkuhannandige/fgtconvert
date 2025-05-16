from flask import Flask, request, send_file, render_template_string
import pandas as pd
import re
import ipaddress
import os

app = Flask(__name__)

def read_policies(file_path):
    try:
        return pd.read_csv(file_path)
    except Exception:
        return pd.read_excel(file_path)

def parse_services(service_field):
    parts = re.split(r'[;,]', str(service_field))
    return [p.strip() for p in parts if p.strip()]

def cidr_to_netmask(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    return str(net.network_address), str(net.netmask)

def generate_address_cli(name, cidr):
    ip, netmask = cidr_to_netmask(cidr)
    return f"""config firewall address
    edit "{name}"
        set subnet {ip} {netmask}
    next
end
"""

def generate_service_cli(name, proto, port):
    proto = proto.upper()
    if proto not in ['TCP', 'UDP']:
        return ""
    return f"""config firewall service custom
    edit "{name}"
        set protocol {proto}
        set {proto.lower()}-portrange {port}
    next
end
"""

def generate_policy_cli(policy_id, name, srcaddr, dstaddr, services):
    service_list = ' '.join(f'"{s}"' for s in services)
    return f"""config firewall policy
    edit {policy_id}
        set name "{name}"
        set srcintf "any"
        set dstintf "any"
        set srcaddr "{srcaddr}"
        set dstaddr "{dstaddr}"
        set service {service_list}
        set schedule "always"
        set action accept
        set logtraffic all
    next
end
"""

@app.route('/')
def upload_form():
    return render_template_string("""
    <html>
        <body>
            <h1>Upload Your Spreadsheet (CSV or Excel)</h1>
            <p><strong>Required Columns:</strong></p>
            <ul>
                <li><code>Policy Name</code> – A unique name for the firewall policy</li>
                <li><code>Source Address</code> – Can be a name or IP address</li>
                <li><code>Source Subnet</code> – If named source is used, provide subnet (e.g. 192.168.1.0/24)</li>
                <li><code>Destination Address</code> – Can be a name or IP address</li>
                <li><code>Destination Subnet</code> – If named destination is used, provide subnet</li>
                <li><code>Service</code> – Comma or semicolon separated list (e.g. TCP/443, UDP/53)</li>
            </ul>
            <p>Note: The application will automatically generate FortiGate CLI for services and addresses.</p>
            <form action="/upload" method="post" enctype="multipart/form-data">
                <input type="file" name="file" accept=".csv,.xlsx" required>
                <input type="submit" value="Upload">
            </form>
            <footer style="margin-top:40px; font-size:small; color:gray;">
                <hr>
                <p>&copy; Irosh Kokkuhannandige</p>
            </footer>
        </body>
    </html>
    """)

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    if file:
        input_file = os.path.join("uploads", file.filename)
        os.makedirs("uploads", exist_ok=True)
        file.save(input_file)

        output_dir = os.path.join("static", "output")
        os.makedirs(output_dir, exist_ok=True)

        df = read_policies(input_file)

        custom_services = {}
        address_objects = {}
        address_cli = []
        service_cli = []
        policy_cli = []

        for idx, row in df.iterrows():
            policy_name = row['Policy Name']
            src = row['Source Address']
            dst = row['Destination Address']
            src_subnet = row.get('Source Subnet')
            dst_subnet = row.get('Destination Subnet')
            services = parse_services(row['Service'])

            service_refs = []

            for svc in services:
                match = re.match(r'^(TCP|UDP)/(\d+)$', svc, re.IGNORECASE)
                if match:
                    proto, port = match.groups()
                    svc_name = f"{proto.upper()}-{port}"
                    if svc_name not in custom_services:
                        custom_services[svc_name] = (proto.upper(), port)
                        service_cli.append(generate_service_cli(svc_name, proto, port))
                    service_refs.append(svc_name)
                else:
                    service_refs.append(svc)

            if src.lower() != "any" and not re.match(r'^\\d+\\.\\d+\\.\\d+\\.\\d+(/\\d+)?$', src):
                if src not in address_objects and pd.notna(src_subnet):
                    address_objects[src] = src_subnet
                    address_cli.append(generate_address_cli(src, src_subnet))

            if dst.lower() != "any" and not re.match(r'^\\d+\\.\\d+\\.\\d+\\.\\d+(/\\d+)?$', dst):
                if dst not in address_objects and pd.notna(dst_subnet):
                    address_objects[dst] = dst_subnet
                    address_cli.append(generate_address_cli(dst, dst_subnet))

            policy_cli.append(
                generate_policy_cli(idx+1, policy_name, src, dst, service_refs)
            )

        address_file = os.path.join(output_dir, "addresses.txt")
        service_file = os.path.join(output_dir, "services.txt")
        policy_file = os.path.join(output_dir, "policies.txt")

        with open(address_file, 'w') as f:
            f.write("\n".join(address_cli))
        with open(service_file, 'w') as f:
            f.write("\n".join(service_cli))
        with open(policy_file, 'w') as f:
            f.write("\n".join(policy_cli))

        return render_template_string("""
        <html>
            <body>
                <h1>Files Generated</h1>
                <p><a href='{{ address_file }}' download>Download Addresses</a></p>
                <p><a href='{{ service_file }}' download>Download Services</a></p>
                <p><a href='{{ policy_file }}' download>Download Policies</a></p>
                <footer style="margin-top:40px; font-size:small; color:gray;">
                    <hr>
                    <p>&copy; Irosh Kokkuhannandige</p>
                </footer>
            </body>
        </html>
        """, address_file=address_file, service_file=service_file, policy_file=policy_file)

if __name__ == '__main__':
    app.run(debug=True)
