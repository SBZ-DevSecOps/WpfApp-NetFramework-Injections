using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using WpfApp_NetFramework_Injections.Vulnerabilities;

namespace WpfApp_NetFramework_Injections
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        // Dictionnaire FR uniquement
        private readonly Dictionary<string, string> labelsFr = new Dictionary<string, string>
        {
            { "Title", "DA01 – Injections" },
            { "Intro", "Quinze payloads d’injection classiques. Volontairement vulnérables pour démo SAST." },

            { "SqlLabel", "1. Injection SQL" },
            { "SqlDesc",  "Concatène l'entrée dans une requête SQL (ADO.NET)." },
            { "SqlButton","Exécuter SQL" },

            { "CmdLabel", "2. Injection de commande OS" },
            { "CmdDesc",  "Exécute cmd.exe /C avec l'entrée utilisateur." },
            { "CmdButton","Exécuter la commande" },

            { "LdapLabel","3. Injection LDAP" },
            { "LdapDesc", "Filtre DirectorySearcher non sécurisé." },
            { "LdapButton","Rechercher LDAP" },

            { "XpathLabel","4. Injection XPath" },
            { "XpathDesc", "XPath fourni par l'utilisateur dans SelectNodes." },
            { "XpathButton","Exécuter XPath" },

            { "XxeLabel", "5. XXE / Injection XML" },
            { "XxeDesc",  "DTD + XmlResolver activés." },
            { "XxeButton","Parser XML" },

            { "XsltLabel","6. Injection XSLT" },
            { "XsltDesc", "Feuille de style contrôlée par l'utilisateur." },
            { "XsltButton","Appliquer XSLT" },

            { "PathLabel","7. Injection de chemin OS" },
            { "PathDesc", "Chemin utilisateur utilisé pour écriture fichier." },
            { "PathButton","Écrire fichier" },

            { "ExprLabel","8. Injection d'expression" },
            { "ExprDesc", "DataTable.Compute(expression)." },
            { "ExprButton","Calculer" },

            { "RegexLabel","9. Injection Regex / ReDoS" },
            { "RegexDesc", "Motif utilisateur compilé et évalué." },
            { "RegexButton","Tester Regex" },

            { "ArgsLabel","10. Injection d'arguments de processus" },
            { "ArgsDesc", "Démarre un exe avec des arguments fournis." },
            { "ArgsButton","Démarrer processus" },

            { "CsvLabel", "11. Injection de formule CSV" },
            { "CsvDesc",  "Écrit une cellule pouvant commencer par =,+,-,@." },
            { "CsvButton","Écrire CSV" },

            { "PsLabel",  "12. Injection PowerShell" },
            { "PsDesc",   "powershell.exe -Command <entrée>." },
            { "PsButton", "Exécuter PowerShell" },

            { "XamlLabel","13. Injection XAML" },
            { "XamlDesc", "XamlReader.Parse sur XAML utilisateur." },
            { "XamlButton","Parser XAML" },

            { "ReflLabel","14. Injection de type (Reflection)" },
            { "ReflDesc", "Type.GetType + Activator.CreateInstance." },
            { "ReflButton","Instancier" },

            { "AsmLabel", "15. Injection via chargement d'assembly" },
            { "AsmDesc",  "Assembly.LoadFrom sur chemin fourni." },
            { "AsmButton","Charger l'assembly" },
        };

        public MainWindow()
        {
            InitializeComponent();

            // Appliquer les libellés FR
            ApplyFrenchLabels();

            // Placeholders
            SqlInput.Text = "bob' OR '1'='1";
            CmdInput.Text = "calc.exe";
            LdapInput.Text = "*) (|(cn=admin)(cn=*))("; // volontairement étrange
            XpathInput.Text = "//user[@name='alice' or '1'='1']";
            XxeInput.Text = "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><r>&xxe;</r>";
            XsltInput.Text = "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'><xsl:template match='/'><out><xsl:value-of select='//msg'/></out></xsl:template></xsl:stylesheet>";
            PathInput.Text = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + "\\..\\exposed\\inj.txt";
            ExprInput.Text = "1+2*3";
            RegexPatternInput.Text = "(a+)+$";
            RegexSampleInput.Text = new string('a', 5000);
            ArgsExeInput.Text = "ping.exe";
            ArgsArgsInput.Text = "127.0.0.1 & calc.exe";
            CsvInput.Text = "=2+2";
            PsInput.Text = "Start-Process calc";
            XamlInput.Text = "<Button xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' Content='XAML!' />";
            ReflInput.Text = "System.Text.StringBuilder, mscorlib";
            AsmInput.Text = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + "\\demo.dll";
        }

        private string Lb(string key) => labelsFr[key];

        private void ApplyFrenchLabels()
        {
            Action<string, string> setTextBlock = (name, key) =>
            {
                if (FindName(name) is TextBlock tb) tb.Text = Lb(key);
            };
            Action<string, string> setButton = (name, key) =>
            {
                if (FindName(name) is Button btn) btn.Content = Lb(key);
            };

            if (FindName("TitleText") is TextBlock title) title.Text = Lb("Title");
            if (FindName("IntroText") is TextBlock intro) intro.Text = Lb("Intro");
            this.Title = Lb("Title");

            setTextBlock("SqlLabel", "SqlLabel"); setTextBlock("SqlDesc", "SqlDesc"); setButton("SqlButton", "SqlButton");
            setTextBlock("CmdLabel", "CmdLabel"); setTextBlock("CmdDesc", "CmdDesc"); setButton("CmdButton", "CmdButton");
            setTextBlock("LdapLabel", "LdapLabel"); setTextBlock("LdapDesc", "LdapDesc"); setButton("LdapButton", "LdapButton");
            setTextBlock("XpathLabel", "XpathLabel"); setTextBlock("XpathDesc", "XpathDesc"); setButton("XpathButton", "XpathButton");
            setTextBlock("XxeLabel", "XxeLabel"); setTextBlock("XxeDesc", "XxeDesc"); setButton("XxeButton", "XxeButton");
            setTextBlock("XsltLabel", "XsltLabel"); setTextBlock("XsltDesc", "XsltDesc"); setButton("XsltButton", "XsltButton");
            setTextBlock("PathLabel", "PathLabel"); setTextBlock("PathDesc", "PathDesc"); setButton("PathButton", "PathButton");
            setTextBlock("ExprLabel", "ExprLabel"); setTextBlock("ExprDesc", "ExprDesc"); setButton("ExprButton", "ExprButton");
            setTextBlock("RegexLabel", "RegexLabel"); setTextBlock("RegexDesc", "RegexDesc"); setButton("RegexButton", "RegexButton");
            setTextBlock("ArgsLabel", "ArgsLabel"); setTextBlock("ArgsDesc", "ArgsDesc"); setButton("ArgsButton", "ArgsButton");
            setTextBlock("CsvLabel", "CsvLabel"); setTextBlock("CsvDesc", "CsvDesc"); setButton("CsvButton", "CsvButton");
            setTextBlock("PsLabel", "PsLabel"); setTextBlock("PsDesc", "PsDesc"); setButton("PsButton", "PsButton");
            setTextBlock("XamlLabel", "XamlLabel"); setTextBlock("XamlDesc", "XamlDesc"); setButton("XamlButton", "XamlButton");
            setTextBlock("ReflLabel", "ReflLabel"); setTextBlock("ReflDesc", "ReflDesc"); setButton("ReflButton", "ReflButton");
            setTextBlock("AsmLabel", "AsmLabel"); setTextBlock("AsmDesc", "AsmDesc"); setButton("AsmButton", "AsmButton");
        }

        // -------- Handlers --------

        private void SqlButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunSqlInjection(SqlInput.Text); SqlResult.Text = "Requête SQL exécutée."; }

        private void CmdButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunCommandInjection(CmdInput.Text); CmdResult.Text = "Commande lancée."; }

        private void LdapButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunLdapInjection(LdapInput.Text); LdapResult.Text = "Recherche LDAP effectuée."; }

        private void XpathButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunXpathInjection(XpathInput.Text); XpathResult.Text = "XPath exécuté."; }

        private void XxeButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunXxeInjection(XxeInput.Text); XxeResult.Text = "XML parsé (XXE possible)."; }

        private void XsltButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunXsltInjection(XsltInput.Text); XsltResult.Text = "XSLT appliqué."; }

        private void PathButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunOsPathInjection(PathInput.Text); PathResult.Text = "Écriture effectuée."; }

        private void ExprButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunExpressionInjection(ExprInput.Text); ExprResult.Text = "Expression calculée."; }

        private void RegexButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunRegexInjection(RegexPatternInput.Text, RegexSampleInput.Text); RegexResult.Text = "Regex testée."; }

        private void ArgsButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunProcessArgsInjection(ArgsExeInput.Text, ArgsArgsInput.Text); ArgsResult.Text = "Processus lancé."; }

        private void CsvButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunCsvFormulaInjection(CsvInput.Text); CsvResult.Text = "CSV écrit (Documents)."; }

        private void PsButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunPowershellInjection(PsInput.Text); PsResult.Text = "PowerShell exécuté."; }

        private void XamlButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunXamlInjection(XamlInput.Text); XamlResult.Text = "XAML parsé."; }

        private void ReflButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunReflectionInjection(ReflInput.Text); ReflResult.Text = "Reflection exécutée."; }

        private void AsmButton_Click(object sender, RoutedEventArgs e)
        { InjectionVuln.RunAssemblyLoadInjection(AsmInput.Text); AsmResult.Text = "Assembly chargé."; }

        // Si ton XAML référence encore cet événement, il ne fera rien (FR only).
        private void LanguageSelector_Changed(object sender, SelectionChangedEventArgs e) { /* FR uniquement : no-op */ }
    }
}
