import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { Brain, Code, BarChart3, Zap, Loader2 } from 'lucide-react';
import { apiRequest } from '@/lib/queryClient';
import { useToast } from '@/hooks/use-toast';

interface GroqAIAnalysisProps {
  visitors: any[];
  packets: any[];
  isActive: boolean;
}

export default function GroqAIAnalysis({ visitors, packets, isActive }: GroqAIAnalysisProps) {
  const [aiMode, setAiMode] = useState<'deploy' | 'designer' | 'analysis'>('analysis');
  const [prompt, setPrompt] = useState('');
  const [autoAnalysis, setAutoAnalysis] = useState(false);
  const [analysis, setAnalysis] = useState('');
  const { toast } = useToast();

  const analysisMutation = useMutation({
    mutationFn: async (data: { mode: string; prompt: string; context: any }) => {
      const response = await fetch('/api/groq-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      return await response.json();
    },
    onSuccess: (data) => {
      setAnalysis(data.analysis);
      toast({
        title: "AI Analysis Complete",
        description: "Educational threat analysis generated successfully"
      });
    },
    onError: () => {
      toast({
        title: "Analysis Failed",
        description: "Unable to generate AI analysis. Check your Groq API configuration.",
        variant: "destructive"
      });
    }
  });

  const runAnalysis = () => {
    const context = {
      visitorCount: visitors.length,
      recentVisitors: visitors.slice(0, 5),
      packetCount: packets.length,
      recentPackets: packets.slice(0, 5)
    };

    let systemPrompt = '';
    switch (aiMode) {
      case 'deploy':
        systemPrompt = 'You are an expert in cybersecurity deployment strategies. Analyze the traffic patterns and suggest deployment tactics for educational red team exercises.';
        break;
      case 'designer':
        systemPrompt = 'You are an expert web designer specializing in social engineering tactics. Suggest HTML/CSS improvements to make phishing simulations more effective for educational purposes.';
        break;
      case 'analysis':
        systemPrompt = 'You are a cybersecurity expert analyzing traffic for educational purposes. Provide insights on visitor behavior, potential attack vectors, and defense strategies.';
        break;
    }

    analysisMutation.mutate({
      mode: aiMode,
      prompt: prompt || systemPrompt,
      context
    });
  };

  const getModeIcon = () => {
    switch (aiMode) {
      case 'deploy': return <Zap className="w-4 h-4" />;
      case 'designer': return <Code className="w-4 h-4" />;
      case 'analysis': return <BarChart3 className="w-4 h-4" />;
    }
  };

  const getModeDescription = () => {
    switch (aiMode) {
      case 'deploy': return 'AI-powered deployment strategy analysis for red team exercises';
      case 'designer': return 'HTML/CSS optimization suggestions for social engineering simulations';
      case 'analysis': return 'Traffic pattern analysis and cybersecurity insights';
    }
  };

  return (
    <Card className="bg-gray-900 border-matrix">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-matrix">
          <Brain className="w-5 h-5" />
          Groq AI Analysis Engine
          {isActive && <Badge variant="secondary" className="bg-green-900 text-green-300">Active</Badge>}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Mode Selection */}
        <div className="space-y-2">
          <label className="text-sm font-medium text-gray-300">Analysis Mode</label>
          <Select value={aiMode} onValueChange={(value: any) => setAiMode(value)}>
            <SelectTrigger className="bg-gray-800 border-gray-600">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="bg-gray-800 border-gray-600">
              <SelectItem value="deploy">
                <div className="flex items-center gap-2">
                  <Zap className="w-4 h-4" />
                  Page Deploy Mode
                </div>
              </SelectItem>
              <SelectItem value="designer">
                <div className="flex items-center gap-2">
                  <Code className="w-4 h-4" />
                  HTML Designer Mode
                </div>
              </SelectItem>
              <SelectItem value="analysis">
                <div className="flex items-center gap-2">
                  <BarChart3 className="w-4 h-4" />
                  HTTP Analysis Mode
                </div>
              </SelectItem>
            </SelectContent>
          </Select>
          <p className="text-xs text-gray-400">{getModeDescription()}</p>
        </div>

        {/* Auto Analysis Toggle */}
        <div className="flex items-center justify-between">
          <label className="text-sm font-medium text-gray-300">Auto Analysis</label>
          <Switch 
            checked={autoAnalysis} 
            onCheckedChange={setAutoAnalysis}
            disabled={!isActive}
          />
        </div>

        {/* Custom Prompt */}
        <div className="space-y-2">
          <label className="text-sm font-medium text-gray-300">Custom Analysis Prompt</label>
          <Textarea
            placeholder="Enter specific analysis questions or leave blank for automatic analysis..."
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            className="bg-gray-800 border-gray-600 text-white"
            rows={3}
          />
        </div>

        {/* Analysis Button */}
        <Button 
          onClick={runAnalysis} 
          disabled={analysisMutation.isPending || !isActive}
          className="w-full bg-matrix hover:bg-matrix/80"
        >
          {analysisMutation.isPending ? (
            <>
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              Analyzing...
            </>
          ) : (
            <>
              {getModeIcon()}
              <span className="ml-2">Run {aiMode.charAt(0).toUpperCase() + aiMode.slice(1)} Analysis</span>
            </>
          )}
        </Button>

        {/* Analysis Results */}
        {analysis && (
          <div className="space-y-2">
            <label className="text-sm font-medium text-gray-300">AI Analysis Results</label>
            <div className="bg-gray-800 border border-gray-600 rounded-lg p-4">
              <pre className="text-sm text-gray-300 whitespace-pre-wrap font-mono">
                {analysis}
              </pre>
            </div>
          </div>
        )}

        {/* Quick Stats */}
        <div className="grid grid-cols-2 gap-4 pt-4 border-t border-gray-700">
          <div className="text-center">
            <div className="text-2xl font-bold text-matrix">{visitors.length}</div>
            <div className="text-xs text-gray-400">Visitors Tracked</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-matrix">{packets.length}</div>
            <div className="text-xs text-gray-400">Packets Captured</div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}