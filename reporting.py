
import pandas as pd
from fpdf import FPDF
import datetime

class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Vulnerability Scan Report', 0, 1, 'C')
        self.set_font('Arial', '', 8)
        self.cell(0, 10, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf_report(vuln_df: pd.DataFrame) -> bytes:
    """Generates a PDF report from a DataFrame of vulnerabilities."""
    if vuln_df.empty:
        return b""

    pdf = PDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Summary Section
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, "Summary", 0, 1)
    pdf.set_font("Arial", size=12)
    
    total_vulns = len(vuln_df)
    high_risk = sum(vuln_df['Risk'] == 'High')
    medium_risk = sum(vuln_df['Risk'] == 'Medium')
    low_risk = sum(vuln_df['Risk'] == 'Low')

    pdf.cell(0, 10, f"- Total Vulnerabilities Found: {total_vulns}", 0, 1)
    pdf.cell(0, 10, f"- High Risk: {high_risk}", 0, 1)
    pdf.cell(0, 10, f"- Medium Risk: {medium_risk}", 0, 1)
    pdf.cell(0, 10, f"- Low Risk: {low_risk}", 0, 1)
    pdf.ln(10)

    # Detailed Vulnerabilities Section
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, "Detailed Findings", 0, 1)
    
    for index, row in vuln_df.iterrows():
        pdf.set_font('Arial', 'B', 12)
        pdf.multi_cell(0, 10, f"Description: {row.get('Description', 'N/A')}")
        
        pdf.set_font('Arial', '', 10)
        pdf.multi_cell(0, 8, f"  Component: {row.get('Component', 'N/A')}")
        pdf.multi_cell(0, 8, f"  CVE ID: {row.get('CVE ID', 'N/A')}")
        pdf.multi_cell(0, 8, f"  CVSS Score: {row.get('CVSS', 'N/A')} ({row.get('Risk', 'Unknown')})")
        pdf.ln(5)

    return pdf.output(dest='S').encode('latin1')

def generate_csv_report(vuln_df: pd.DataFrame) -> str:
    """Generates a CSV report string from a DataFrame."""
    if vuln_df.empty:
        return ""
    return vuln_df.to_csv(index=False).encode('utf-8')
