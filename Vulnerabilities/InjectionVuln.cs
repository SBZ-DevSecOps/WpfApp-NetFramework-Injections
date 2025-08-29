using System;
using System.Data;
using System.Data.SqlClient;
using System.DirectoryServices;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Markup;
using System.Xml;
using System.Xml.Xsl;

namespace WpfApp_NetFramework_Injections.Vulnerabilities
{
    public static class InjectionVuln
    {
        // 1) SQL Injection (ADO.NET, concat)
        public static void RunSqlInjection(string userInput)
        {
            try
            {
                // Intentionally vulnerable: concatenation in SQL command
                var connStr = "Data Source=.;Initial Catalog=master;Integrated Security=True";
                using (var conn = new SqlConnection(connStr))
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = "SELECT name FROM sys.objects WHERE type = 'U' AND name = '" + userInput + "'";
                    conn.Open();
                    using (var r = cmd.ExecuteReader())
                    {
                        int count = 0;
                        while (r.Read()) count++;
                        MessageBox.Show("Query executed. Rows: " + count, "SQL Injection (demo)");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("SQL error: " + ex.Message, "SQL Injection");
            }
        }

        // 2) OS Command Injection
        public static void RunCommandInjection(string payload)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/C " + payload, // ❌ unsanitized
                    UseShellExecute = true
                });
                MessageBox.Show("Command executed: " + payload, "OS Command Injection");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Process error: " + ex.Message, "OS Command Injection");
            }
        }

        // 3) LDAP Injection (DirectorySearcher filter)
        public static void RunLdapInjection(string filterInput)
        {
            try
            {
                var ds = new DirectorySearcher();
                ds.Filter = "(&(objectClass=user)(cn=" + filterInput + "))"; // ❌ unsafe
                ds.PropertiesToLoad.Add("cn");
                var res = ds.FindOne();
                MessageBox.Show("LDAP search performed. Result: " + (res != null ? "found" : "none"), "LDAP Injection");
            }
            catch (Exception ex)
            {
                MessageBox.Show("LDAP error: " + ex.Message, "LDAP Injection");
            }
        }

        // 4) XPath Injection
        public static void RunXpathInjection(string xpathExpr)
        {
            try
            {
                var xml = "<users><user name='alice'/><user name='bob'/></users>";
                var doc = new XmlDocument();
                doc.LoadXml(xml);
                var nodes = doc.SelectNodes(xpathExpr); // ❌ user-controlled
                MessageBox.Show("XPath nodes count: " + (nodes != null ? nodes.Count.ToString() : "0"), "XPath Injection");
            }
            catch (Exception ex)
            {
                MessageBox.Show("XPath error: " + ex.Message, "XPath Injection");
            }
        }

        // 5) XXE / XML Injection (DTD enabled)
        public static void RunXxeInjection(string xmlWithDtd)
        {
            try
            {
                var settings = new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Parse,      // ❌ allow DTD
                    XmlResolver = new XmlUrlResolver()        // ❌ external entity resolution
                };
                using (var sr = new StringReader(xmlWithDtd))
                using (var xr = XmlReader.Create(sr, settings))
                {
                    var doc = new XmlDocument();
                    doc.XmlResolver = new XmlUrlResolver();   // ❌
                    doc.Load(xr);
                    MessageBox.Show("XML loaded. Root: " + (doc.DocumentElement != null ? doc.DocumentElement.Name : "null"), "XXE/XML Injection");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("XML error: " + ex.Message, "XXE/XML Injection");
            }
        }

        // 6) XSLT Injection (user-provided XSL)
        public static void RunXsltInjection(string xslString)
        {
            try
            {
                var transform = new XslCompiledTransform();
                using (var sr = new StringReader(xslString))
                using (var xr = XmlReader.Create(sr))
                {
                    transform.Load(xr); // ❌ user-controlled stylesheet
                }
                var inputXml = "<root><msg>Hello</msg></root>";
                string output;
                using (var ms = new MemoryStream())
                using (var xw = XmlWriter.Create(ms))
                {
                    using (var ir = XmlReader.Create(new StringReader(inputXml)))
                    {
                        transform.Transform(ir, xw);
                    }
                    xw.Flush();
                    output = Encoding.UTF8.GetString(ms.ToArray());
                }
                MessageBox.Show("XSLT applied.\nOutput preview:\n" + (output.Length > 200 ? output.Substring(0, 200) + "..." : output), "XSLT Injection");
            }
            catch (Exception ex)
            {
                MessageBox.Show("XSLT error: " + ex.Message, "XSLT Injection");
            }
        }

        // 7) OS Path Injection (Path Traversal)
        public static void RunOsPathInjection(string path)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                File.WriteAllText(path, "INJECTED_CONTENT");
                MessageBox.Show("Wrote to: " + path, "OS Path Injection");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Path error: " + ex.Message, "OS Path Injection");
            }
        }

        // 8) Expression Language Injection (DataTable.Compute)
        public static void RunExpressionInjection(string expression)
        {
            try
            {
                var t = new DataTable();
                var result = t.Compute(expression, null); // ❌ user-controlled expression
                MessageBox.Show("Compute('" + expression + "') = " + (result != null ? result.ToString() : "null"), "Expression Injection");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Expression error: " + ex.Message, "Expression Injection");
            }
        }

        // 9) Regex Injection / ReDoS
        public static void RunRegexInjection(string pattern, string sample)
        {
            try
            {
                var rx = new Regex(pattern); // ❌ user-controlled
                var ok = rx.IsMatch(sample);
                MessageBox.Show("Regex.IsMatch = " + ok, "Regex Injection / ReDoS");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Regex error: " + ex.Message, "Regex Injection");
            }
        }

        // 10) Process Arguments Injection
        public static void RunProcessArgsInjection(string exe, string args)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = exe,       // ❌ user-controlled tool
                    Arguments = args,     // ❌ user-controlled args
                    UseShellExecute = true
                });
                MessageBox.Show("Started: " + exe + " " + args, "Process Args Injection");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Process error: " + ex.Message, "Process Args Injection");
            }
        }

        // 11) CSV Formula Injection
        public static void RunCsvFormulaInjection(string cell)
        {
            try
            {
                var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "inj_formula.csv");
                var line = cell; // ❌ e.g. "=CMD|' /C calc'!A0"
                File.WriteAllText(path, line + Environment.NewLine);
                MessageBox.Show("CSV written: " + path, "CSV Formula Injection");
            }
            catch (Exception ex)
            {
                MessageBox.Show("CSV error: " + ex.Message, "CSV Formula Injection");
            }
        }

        // 12) PowerShell Injection
        public static void RunPowershellInjection(string ps = "powershell.exe")
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = ps,
                    Arguments = "-NoProfile -Command " + ps, // ❌ user-controlled
                    UseShellExecute = true
                });
                MessageBox.Show("PowerShell executed: " + ps, "PowerShell Injection");
            }
            catch (Exception ex)
            {
                MessageBox.Show("PowerShell error: " + ex.Message, "PowerShell Injection");
            }
        }

        // 13) XAML Injection (XamlReader.Parse)
        public static void RunXamlInjection(string xaml)
        {
            try
            {
                object obj = XamlReader.Parse(xaml); // ❌ user-controlled XAML
                MessageBox.Show("XAML parsed to: " + (obj != null ? obj.GetType().FullName : "null"), "XAML Injection");
            }
            catch (Exception ex)
            {
                MessageBox.Show("XAML error: " + ex.Message, "XAML Injection");
            }
        }

        // 14) Reflection / Type Name Injection
        public static void RunReflectionInjection(string typeName)
        {
            try
            {
                var t = Type.GetType(typeName, false); // ❌ user-controlled
                var inst = t != null ? Activator.CreateInstance(t) : null;
                MessageBox.Show("Type: " + (t != null ? t.FullName : "null") +
                                "\nInstance: " + (inst != null ? inst.ToString() : "null"),
                                "Reflection Injection");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Reflection error: " + ex.Message, "Reflection Injection");
            }
        }

        // 15) Assembly Load Injection
        public static void RunAssemblyLoadInjection(string asmPath)
        {
            try
            {
                var asm = Assembly.LoadFrom(asmPath); // ❌ user-controlled
                var types = asm.GetTypes();
                MessageBox.Show("Loaded " + types.Length + " types from " + asmPath, "Assembly Load Injection");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Assembly load error: " + ex.Message, "Assembly Load Injection");
            }
        }
    }
}
