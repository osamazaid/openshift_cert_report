# OpenShift Certificate Exporter
This Python script provides a robust and efficient way to list all TLS certificates across your OpenShift namespaces, extract their expiration dates and issuers, and export this information into a structured Excel file. It also generates a separate sheet for certificates expiring within the next two weeks, helping you proactively manage certificate renewals.

The script leverages the oc command-line tool for interacting with your OpenShift cluster and processes namespaces in parallel to significantly speed up data collection, especially in large environments.

# Features
- Comprehensive Certificate Discovery: Scans secrets of type kubernetes.io/tls, OpenShift Routes (for embedded certificates), Kubernetes Ingresses (by referencing their secrets), and Cert-Manager Certificate custom resources (if Cert-Manager is installed).
- Parallel Processing: Utilizes Python's concurrent.futures.ThreadPoolExecutor to query multiple namespaces concurrently, drastically reducing execution time for large clusters.
- Detailed Certificate Information: Extracts:
  - Namespace
  - Certificate Name
  - Source Type (Secret, Route, Ingress, Cert-Manager)0
  - Expiration Date
  - Issuer 
  - Status (Valid, Expired, Expiring Soon)
  - Remaining Days until expiration
  - Excel Export: Generates a .xlsx file with two sheets:
  - All Certificates: A complete list of all discovered certificates.
  - Expiring Soon: A filtered list showing only certificates that will expire within the next 14 days.
  - Intelligent Cert-Manager Check: Automatically detects if the Cert-Manager operator is installed in your cluster and only queries its custom resources if present, saving time and resources.
  - Graceful Error Handling: Provides informative messages for access denied errors or when specific resource types (like Cert-Manager CRDs) are not found.
  - Warning Suppression: Handles openpyxl's UserWarning for long issuer strings, ensuring clean console output without affecting functionality.

# Prerequisites
Before running this script, ensure you have the following:

- Python 3.x: Installed on your system.
- OpenShift oc CLI Tool: The oc command-line tool must be installed and configured to connect to your OpenShift cluster. The script uses your current kubeconfig context.
- Verify by running oc whoami or oc get namespaces in your terminal.
- Python Libraries: Install the required Python packages using pip:
~~~
pip install openpyxl cryptography
~~~
# Installation
Clone the Repository (or download the script):
~~~
git clone https://github.com/osamazaid/openshift_cert_report.git
cd openshift_cert_report
~~~

Install Dependencies:
~~~
pip install openpyxl cryptography
~~~
Usage
To run the script and generate the certificate report:
~~~
python openshift_cert_report.py
~~~

The script will print progress messages to the console. Once completed, an Excel file named openshift_certificates_report.xlsx will be created in the same directory where you run the script.

**Output**
The generated openshift_certificates_report.xlsx file will contain two sheets:

Sheet 1: All Certificates
- Certificates with Expired status will be highlighted in light red.
- Certificates with Expiring Soon status will be highlighted in light yellow.

Sheet 2: Expiring Soon

# Notes and Considerations
- Permissions: The oc user context under which the script is run must have sufficient get and list permissions for namespaces, secrets, routes, ingresses, and customresourcedefinitions (for Cert-Manager check) across all relevant namespaces.
- Large Clusters: While parallel processing significantly speeds up the script, very large clusters with thousands of namespaces and hundreds of thousands of resources might still take some time.
- Issuer String Truncation: The script truncates very long issuer strings in the Excel output to ensure compatibility with openpyxl's internal attribute length limits. The full issuer information is still available in the raw certificate data if needed.
- Error Reporting: The script prints errors related to oc command failures or access denied issues directly to the console.
