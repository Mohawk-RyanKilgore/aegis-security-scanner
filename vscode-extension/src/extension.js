const vscode = require('vscode');
const { exec, spawn, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

let diagnosticCollection;
let statusBarItem;
let outputChannel;
let extensionContext;

// Required Python packages for full functionality
const REQUIRED_PACKAGES = ['bandit', 'reportlab'];
const OPTIONAL_PACKAGES = ['gitpython']; // For git history scanning

/**
 * Aegis Security Scanner - VS Code Extension
 * @param {vscode.ExtensionContext} context
 */
async function activate(context) {
    console.log('Aegis Security Scanner is now active');
    extensionContext = context;

    // Create diagnostic collection for showing issues
    diagnosticCollection = vscode.languages.createDiagnosticCollection('aegis');
    context.subscriptions.push(diagnosticCollection);

    // Create output channel for logs
    outputChannel = vscode.window.createOutputChannel('Aegis Security');
    context.subscriptions.push(outputChannel);

    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = 'aegis.scanWorkspace';
    statusBarItem.text = '$(shield) Aegis';
    statusBarItem.tooltip = 'Click to scan workspace for security issues';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('aegis.scanWorkspace', () => scanWorkspace()),
        vscode.commands.registerCommand('aegis.scanCurrentFile', () => scanCurrentFile()),
        vscode.commands.registerCommand('aegis.scanFolder', (uri) => scanFolder(uri)),
        vscode.commands.registerCommand('aegis.generatePdfReport', () => generatePdfReport()),
        vscode.commands.registerCommand('aegis.clearDiagnostics', () => clearDiagnostics()),
        vscode.commands.registerCommand('aegis.setupWizard', () => runSetupWizard()),
        vscode.commands.registerCommand('aegis.installDependencies', () => installDependencies())
    );

    // Auto-scan on save (if enabled)
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((document) => {
            const config = vscode.workspace.getConfiguration('aegis');
            if (config.get('autoScanOnSave')) {
                scanFile(document.uri.fsPath);
            }
        })
    );

    // First-run setup wizard
    const hasCompletedSetup = context.globalState.get('hasCompletedSetup');
    if (!hasCompletedSetup) {
        await runSetupWizard();
    } else {
        // Quick check on subsequent runs
        const pythonOk = await checkPython();
        if (!pythonOk) {
            vscode.window.showWarningMessage(
                'Aegis: Python not found. Some features may not work.',
                'Run Setup'
            ).then((selection) => {
                if (selection === 'Run Setup') {
                    runSetupWizard();
                }
            });
        }
    }
}

/**
 * Run the first-time setup wizard
 */
async function runSetupWizard() {
    outputChannel.appendLine('=== Aegis Setup Wizard ===');
    outputChannel.show();

    // Step 1: Check Python
    statusBarItem.text = '$(sync~spin) Checking Python...';
    const pythonResult = await checkPythonDetailed();
    
    if (!pythonResult.found) {
        const choice = await vscode.window.showErrorMessage(
            'Aegis requires Python 3.7+ to run. Python was not found on your system.',
            'Download Python',
            'Configure Path',
            'Cancel'
        );
        
        if (choice === 'Download Python') {
            vscode.env.openExternal(vscode.Uri.parse('https://www.python.org/downloads/'));
            vscode.window.showInformationMessage('After installing Python, restart VS Code and run "Aegis: Setup Wizard" from the command palette.');
        } else if (choice === 'Configure Path') {
            vscode.commands.executeCommand('workbench.action.openSettings', 'aegis.pythonPath');
        }
        statusBarItem.text = '$(shield) Aegis ⚠️';
        return;
    }

    outputChannel.appendLine(`✓ Python found: ${pythonResult.version} at ${pythonResult.path}`);

    // Step 2: Check required packages
    statusBarItem.text = '$(sync~spin) Checking dependencies...';
    const missingPackages = await checkPackages();
    
    if (missingPackages.length > 0) {
        outputChannel.appendLine(`✗ Missing packages: ${missingPackages.join(', ')}`);
        
        const choice = await vscode.window.showWarningMessage(
            `Aegis needs these Python packages: ${missingPackages.join(', ')}`,
            'Install Now',
            'Skip',
            'Cancel'
        );
        
        if (choice === 'Install Now') {
            await installDependencies(missingPackages);
        } else if (choice === 'Cancel') {
            statusBarItem.text = '$(shield) Aegis ⚠️';
            return;
        }
    } else {
        outputChannel.appendLine('✓ All required packages installed');
    }

    // Step 3: Verify scanner
    statusBarItem.text = '$(sync~spin) Verifying scanner...';
    const scannerPath = getScannerPath();
    
    if (scannerPath) {
        outputChannel.appendLine(`✓ Scanner found: ${scannerPath}`);
    } else {
        outputChannel.appendLine('✗ Scanner not found');
        vscode.window.showErrorMessage('Aegis scanner file not found. Please reinstall the extension.');
        statusBarItem.text = '$(shield) Aegis ⚠️';
        return;
    }

    // Setup complete!
    statusBarItem.text = '$(shield) Aegis';
    extensionContext.globalState.update('hasCompletedSetup', true);
    
    outputChannel.appendLine('=== Setup Complete! ===');
    
    vscode.window.showInformationMessage(
        'Aegis Security Scanner is ready! Press Ctrl+Shift+A to scan the current file.',
        'Scan Workspace',
        'View Output'
    ).then((selection) => {
        if (selection === 'Scan Workspace') {
            scanWorkspace();
        } else if (selection === 'View Output') {
            outputChannel.show();
        }
    });
}

/**
 * Check if Python is available
 */
async function checkPython() {
    const result = await checkPythonDetailed();
    return result.found;
}

/**
 * Detailed Python check
 */
async function checkPythonDetailed() {
    const config = vscode.workspace.getConfiguration('aegis');
    const pythonPath = config.get('pythonPath') || 'python';
    
    // Try multiple Python commands
    const pythonCommands = [pythonPath, 'python3', 'python', 'py -3', 'py'];
    
    for (const cmd of pythonCommands) {
        try {
            const version = execSync(`${cmd} --version 2>&1`, { encoding: 'utf8', timeout: 5000 }).trim();
            if (version.includes('Python 3')) {
                // Save working Python path
                if (cmd !== pythonPath && cmd !== 'python') {
                    await config.update('pythonPath', cmd, vscode.ConfigurationTarget.Global);
                }
                return { found: true, version, path: cmd };
            }
        } catch (e) {
            // Try next command
        }
    }
    
    return { found: false };
}

/**
 * Check which required packages are missing
 */
async function checkPackages() {
    const config = vscode.workspace.getConfiguration('aegis');
    const pythonPath = config.get('pythonPath') || 'python';
    const missing = [];
    
    for (const pkg of REQUIRED_PACKAGES) {
        try {
            execSync(`${pythonPath} -c "import ${pkg}"`, { encoding: 'utf8', timeout: 5000 });
        } catch (e) {
            missing.push(pkg);
        }
    }
    
    return missing;
}

/**
 * Install missing Python dependencies
 */
async function installDependencies(packages = null) {
    const config = vscode.workspace.getConfiguration('aegis');
    const pythonPath = config.get('pythonPath') || 'python';
    
    if (!packages) {
        packages = await checkPackages();
        if (packages.length === 0) {
            vscode.window.showInformationMessage('All dependencies are already installed!');
            return;
        }
    }
    
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Installing Aegis dependencies...',
        cancellable: false
    }, async (progress) => {
        for (let i = 0; i < packages.length; i++) {
            const pkg = packages[i];
            progress.report({ 
                message: `Installing ${pkg} (${i + 1}/${packages.length})...`,
                increment: (100 / packages.length)
            });
            
            try {
                outputChannel.appendLine(`Installing ${pkg}...`);
                execSync(`${pythonPath} -m pip install ${pkg}`, { 
                    encoding: 'utf8', 
                    timeout: 120000 
                });
                outputChannel.appendLine(`✓ ${pkg} installed`);
            } catch (e) {
                outputChannel.appendLine(`✗ Failed to install ${pkg}: ${e.message}`);
                vscode.window.showErrorMessage(`Failed to install ${pkg}. Try manually: pip install ${pkg}`);
            }
        }
    });
    
    // Verify installation
    const stillMissing = await checkPackages();
    if (stillMissing.length === 0) {
        vscode.window.showInformationMessage('All dependencies installed successfully!');
        extensionContext.globalState.update('hasCompletedSetup', true);
    } else {
        vscode.window.showWarningMessage(`Some packages failed to install: ${stillMissing.join(', ')}`);
    }
}

function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
}

/**
 * Get the path to the security scanner
 */
function getScannerPath() {
    const config = vscode.workspace.getConfiguration('aegis');
    let scannerPath = config.get('scannerPath');
    
    if (!scannerPath) {
        // Use bundled scanner or look in common locations
        const extensionPath = path.dirname(__dirname);
        const bundledPath = path.join(extensionPath, '..', 'aegis.py');
        
        if (fs.existsSync(bundledPath)) {
            return bundledPath;
        }
        
        // Try user's home directory
        const homeDir = process.env.USERPROFILE || process.env.HOME;
        const homePath = path.join(homeDir, 'aegis.py');
        if (fs.existsSync(homePath)) {
            return homePath;
        }
        
        // Try projects folder
        const projectsPath = path.join(homeDir, 'projects', 'aegis-security-scanner', 'aegis.py');
        if (fs.existsSync(projectsPath)) {
            return projectsPath;
        }

        // Try pip installed location
        const pipPath = path.join(homeDir, 'AppData', 'Local', 'Programs', 'Python', 'Python311', 'Scripts', 'aegis.py');
        if (fs.existsSync(pipPath)) {
            return pipPath;
        }
        
        vscode.window.showErrorMessage(
            'Aegis scanner not found. Install with: pip install aegis-security-scanner',
            'Open Settings'
        ).then((selection) => {
            if (selection === 'Open Settings') {
                vscode.commands.executeCommand('workbench.action.openSettings', 'aegis.scannerPath');
            }
        });
        return null;
    }
    
    return scannerPath;
}

/**
 * Run the security scanner and parse results
 */
async function runScanner(targetPath, options = {}) {
    const scannerPath = getScannerPath();
    if (!scannerPath) return null;

    const config = vscode.workspace.getConfiguration('aegis');
    const pythonPath = config.get('pythonPath') || 'python';

    return new Promise((resolve, reject) => {
        const args = [scannerPath, targetPath, '--json'];
        
        if (config.get('scanGitHistory')) {
            args.push('--git-history');
        }
        
        if (options.pdf) {
            args.push('--pdf');
        }

        outputChannel.appendLine(`Running: ${pythonPath} ${args.join(' ')}`);
        statusBarItem.text = '$(sync~spin) Scanning...';

        const process = spawn(pythonPath, args, {
            cwd: path.dirname(targetPath)
        });

        let stdout = '';
        let stderr = '';

        process.stdout.on('data', (data) => {
            stdout += data.toString();
        });

        process.stderr.on('data', (data) => {
            stderr += data.toString();
        });

        process.on('close', (code) => {
            statusBarItem.text = '$(shield) Aegis';
            outputChannel.appendLine(stdout);
            
            if (stderr) {
                outputChannel.appendLine('STDERR: ' + stderr);
            }

            // Try to parse JSON from the output
            try {
                const jsonPath = path.join(path.dirname(targetPath), 'security_report.json');
                if (options.pdf) {
                    resolve({ success: true, pdfGenerated: true });
                } else if (fs.existsSync(jsonPath)) {
                    const data = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
                    fs.unlinkSync(jsonPath);
                    resolve(data);
                } else {
                    resolve({ success: true, rawOutput: stdout });
                }
            } catch (e) {
                resolve({ success: true, rawOutput: stdout });
            }
        });

        process.on('error', (err) => {
            statusBarItem.text = '$(shield) Aegis';
            reject(err);
        });
    });
}

/**
 * Convert scanner results to VS Code diagnostics
 */
function createDiagnostics(results, basePath) {
    const diagnosticsMap = new Map();
    const config = vscode.workspace.getConfiguration('aegis');
    const showFixes = config.get('showFixSuggestions');

    const allIssues = [
        ...(results.results?.bandit?.issues || []),
        ...(results.results?.js?.issues || []),
        ...(results.results?.cpp?.issues || []),
        ...(results.results?.docker?.issues || []),
        ...(results.results?.iac?.issues || []),
        ...(results.results?.secrets?.findings || []),
    ];

    for (const issue of allIssues) {
        const filePath = issue.file;
        if (!filePath) continue;

        const fullPath = path.isAbsolute(filePath) ? filePath : path.join(basePath, filePath);
        const uri = vscode.Uri.file(fullPath);

        const line = Math.max(0, (issue.line || 1) - 1);
        const range = new vscode.Range(line, 0, line, 1000);

        let severity = vscode.DiagnosticSeverity.Warning;
        const issueSeverity = (issue.severity || 'MEDIUM').toUpperCase();
        if (issueSeverity === 'HIGH' || issueSeverity === 'CRITICAL') {
            severity = vscode.DiagnosticSeverity.Error;
        } else if (issueSeverity === 'LOW') {
            severity = vscode.DiagnosticSeverity.Information;
        }

        let message = issue.issue || issue.type || 'Security issue';
        if (issue.cwe) {
            message += ` (${issue.cwe})`;
        }
        if (showFixes && issue.fix) {
            message += `\n\n💡 FIX: ${issue.fix}`;
        }

        const diagnostic = new vscode.Diagnostic(range, message, severity);
        diagnostic.source = 'Aegis';
        diagnostic.code = issue.id || issue.cwe || 'security';

        const key = uri.toString();
        if (!diagnosticsMap.has(key)) {
            diagnosticsMap.set(key, []);
        }
        diagnosticsMap.get(key).push(diagnostic);
    }

    return diagnosticsMap;
}

/**
 * Scan the entire workspace
 */
async function scanWorkspace() {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) {
        vscode.window.showWarningMessage('No workspace folder open');
        return;
    }

    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Scanning workspace for security issues...',
        cancellable: false
    }, async () => {
        try {
            const results = await runScanner(workspaceFolder.uri.fsPath);
            if (results && results.results) {
                const diagnosticsMap = createDiagnostics(results, workspaceFolder.uri.fsPath);
                
                diagnosticCollection.clear();
                for (const [uriString, diagnostics] of diagnosticsMap) {
                    diagnosticCollection.set(vscode.Uri.parse(uriString), diagnostics);
                }

                const totalIssues = results.total_issues || 0;
                const riskScore = results.risk_score || 0;
                
                if (totalIssues > 0) {
                    vscode.window.showWarningMessage(
                        `Aegis found ${totalIssues} security issues (Risk: ${riskScore}/100)`,
                        'Show Problems',
                        'Generate Report'
                    ).then((selection) => {
                        if (selection === 'Show Problems') {
                            vscode.commands.executeCommand('workbench.actions.view.problems');
                        } else if (selection === 'Generate Report') {
                            generatePdfReport();
                        }
                    });
                } else {
                    vscode.window.showInformationMessage('Aegis: No security issues found! ✅');
                }
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Scan failed: ${error.message}`);
            outputChannel.appendLine(`Error: ${error}`);
        }
    });
}

/**
 * Scan the current file
 */
async function scanCurrentFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No file open');
        return;
    }

    await scanFile(editor.document.uri.fsPath);
}

/**
 * Scan a specific file
 */
async function scanFile(filePath) {
    vscode.window.withProgress({
        location: vscode.ProgressLocation.Window,
        title: 'Scanning file...',
    }, async () => {
        try {
            const results = await runScanner(filePath);
            if (results && results.results) {
                const diagnosticsMap = createDiagnostics(results, path.dirname(filePath));
                
                const uri = vscode.Uri.file(filePath);
                const diagnostics = diagnosticsMap.get(uri.toString()) || [];
                diagnosticCollection.set(uri, diagnostics);

                if (diagnostics.length > 0) {
                    vscode.window.showWarningMessage(`Aegis found ${diagnostics.length} security issues in this file`);
                }
            }
        } catch (error) {
            outputChannel.appendLine(`Error scanning file: ${error}`);
        }
    });
}

/**
 * Scan a folder from the explorer context menu
 */
async function scanFolder(uri) {
    if (!uri) return;

    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Scanning folder for security issues...',
        cancellable: false
    }, async () => {
        try {
            const results = await runScanner(uri.fsPath);
            if (results && results.results) {
                const diagnosticsMap = createDiagnostics(results, uri.fsPath);
                
                for (const [uriString, diagnostics] of diagnosticsMap) {
                    diagnosticCollection.set(vscode.Uri.parse(uriString), diagnostics);
                }

                const totalIssues = results.total_issues || 0;
                if (totalIssues > 0) {
                    vscode.window.showWarningMessage(
                        `Aegis found ${totalIssues} security issues in folder`,
                        'Show Problems'
                    ).then((selection) => {
                        if (selection === 'Show Problems') {
                            vscode.commands.executeCommand('workbench.actions.view.problems');
                        }
                    });
                } else {
                    vscode.window.showInformationMessage('Aegis: No security issues found in folder! ✅');
                }
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Scan failed: ${error.message}`);
        }
    });
}

/**
 * Generate PDF report
 */
async function generatePdfReport() {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) {
        vscode.window.showWarningMessage('No workspace folder open');
        return;
    }

    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Generating security report...',
        cancellable: false
    }, async () => {
        try {
            const scannerPath = getScannerPath();
            const config = vscode.workspace.getConfiguration('aegis');
            const pythonPath = config.get('pythonPath') || 'python';

            await new Promise((resolve, reject) => {
                const args = [scannerPath, workspaceFolder.uri.fsPath, '--pdf'];
                
                exec(`"${pythonPath}" ${args.map(a => `"${a}"`).join(' ')}`, {
                    cwd: workspaceFolder.uri.fsPath
                }, (error, stdout, stderr) => {
                    if (error && !stdout.includes('PDF report saved')) {
                        reject(error);
                    } else {
                        resolve();
                    }
                });
            });

            const pdfPath = path.join(workspaceFolder.uri.fsPath, 'security_report.pdf');
            if (fs.existsSync(pdfPath)) {
                vscode.window.showInformationMessage(
                    'PDF report generated!',
                    'Open Report'
                ).then((selection) => {
                    if (selection === 'Open Report') {
                        vscode.env.openExternal(vscode.Uri.file(pdfPath));
                    }
                });
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to generate report: ${error.message}`);
        }
    });
}

/**
 * Clear all diagnostics
 */
function clearDiagnostics() {
    diagnosticCollection.clear();
    vscode.window.showInformationMessage('Aegis: Security diagnostics cleared');
}

module.exports = {
    activate,
    deactivate
};
