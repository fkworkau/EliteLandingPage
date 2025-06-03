
import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { 
  Users, 
  Plus, 
  Edit3, 
  Trash2, 
  Shield, 
  UserCheck, 
  UserX,
  Bot,
  Key
} from "lucide-react";

interface User {
  id: number;
  username: string;
  role: string;
  active: boolean;
  lastLogin: string | null;
  hasTelegramBot: boolean;
  createdAt: string;
}

export default function UserManagement() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showAddUser, setShowAddUser] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [newUser, setNewUser] = useState({
    username: "",
    password: "",
    role: "operator",
    botToken: ""
  });
  const [testingBotToken, setTestingBotToken] = useState(false);

  // Fetch all users
  const { data: users, refetch: refetchUsers } = useQuery({
    queryKey: ["/api/admin/users"],
    refetchInterval: 10000
  });

  // Create user mutation
  const createUserMutation = useMutation({
    mutationFn: async (userData: any) => {
      const response = await apiRequest("POST", "/api/admin/users", userData);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "User Created",
        description: "New user has been successfully created",
      });
      setNewUser({ username: "", password: "", role: "operator", botToken: "" });
      setShowAddUser(false);
      refetchUsers();
    },
    onError: (error: any) => {
      toast({
        title: "Creation Failed",
        description: error.message || "Failed to create user",
        variant: "destructive",
      });
    }
  });

  // Update user mutation
  const updateUserMutation = useMutation({
    mutationFn: async ({ userId, userData }: { userId: number; userData: any }) => {
      const response = await apiRequest("PUT", `/api/admin/users/${userId}`, userData);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "User Updated",
        description: "User has been successfully updated",
      });
      setEditingUser(null);
      refetchUsers();
    }
  });

  // Delete user mutation
  const deleteUserMutation = useMutation({
    mutationFn: async (userId: number) => {
      const response = await apiRequest("DELETE", `/api/admin/users/${userId}`);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "User Deleted",
        description: "User has been successfully deleted",
      });
      refetchUsers();
    }
  });

  // Test bot token mutation
  const testBotTokenMutation = useMutation({
    mutationFn: async (botToken: string) => {
      const response = await apiRequest("POST", "/api/admin/telegram/test", { botToken });
      return response.json();
    },
    onSuccess: (data) => {
      if (data.valid) {
        toast({
          title: "Bot Token Valid",
          description: `Bot: ${data.botInfo.first_name} (@${data.botInfo.username})`,
        });
      } else {
        toast({
          title: "Invalid Bot Token",
          description: data.error || "Token validation failed",
          variant: "destructive",
        });
      }
    }
  });

  const handleCreateUser = () => {
    if (!newUser.username || !newUser.password) {
      toast({
        title: "Validation Error",
        description: "Username and password are required",
        variant: "destructive",
      });
      return;
    }
    createUserMutation.mutate(newUser);
  };

  const handleTestBotToken = () => {
    if (!newUser.botToken) {
      toast({
        title: "No Token",
        description: "Enter a bot token to test",
        variant: "destructive",
      });
      return;
    }
    setTestingBotToken(true);
    testBotTokenMutation.mutate(newUser.botToken);
    setTimeout(() => setTestingBotToken(false), 2000);
  };

  const getRoleBadgeColor = (role: string) => {
    switch (role) {
      case 'admin': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'operator': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'analyst': return 'bg-green-500/20 text-green-400 border-green-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <Users className="text-blue-400 w-6 h-6" />
          <h2 className="text-xl font-bold text-white">User Management</h2>
        </div>
        <Button
          onClick={() => setShowAddUser(true)}
          className="bg-green-600 hover:bg-green-700 text-white"
        >
          <Plus className="w-4 h-4 mr-2" />
          Add User
        </Button>
      </div>

      {/* Add User Form */}
      {showAddUser && (
        <Card className="bg-gray-900 border-gray-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center">
              <UserCheck className="w-5 h-5 mr-2 text-green-400" />
              Create New User
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label className="text-gray-300">Username</Label>
                <Input
                  value={newUser.username}
                  onChange={(e) => setNewUser(prev => ({ ...prev, username: e.target.value }))}
                  className="bg-gray-800 border-gray-700 text-white"
                  placeholder="Enter username"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-gray-300">Password</Label>
                <Input
                  type="password"
                  value={newUser.password}
                  onChange={(e) => setNewUser(prev => ({ ...prev, password: e.target.value }))}
                  className="bg-gray-800 border-gray-700 text-white"
                  placeholder="Enter password"
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label className="text-gray-300">Role</Label>
              <Select value={newUser.role} onValueChange={(value) => setNewUser(prev => ({ ...prev, role: value }))}>
                <SelectTrigger className="bg-gray-800 border-gray-700 text-white">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="admin">Admin - Full Access</SelectItem>
                  <SelectItem value="operator">Operator - Tactical Operations</SelectItem>
                  <SelectItem value="analyst">Analyst - Intelligence Only</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label className="text-gray-300 flex items-center">
                <Bot className="w-4 h-4 mr-2" />
                Telegram Bot Token (Optional)
              </Label>
              <div className="flex space-x-2">
                <Input
                  value={newUser.botToken}
                  onChange={(e) => setNewUser(prev => ({ ...prev, botToken: e.target.value }))}
                  className="bg-gray-800 border-gray-700 text-white flex-1"
                  placeholder="Bot token from @BotFather"
                />
                <Button
                  onClick={handleTestBotToken}
                  disabled={testingBotToken}
                  className="bg-blue-600 hover:bg-blue-700"
                >
                  <Key className="w-4 h-4" />
                  Test
                </Button>
              </div>
              <p className="text-xs text-gray-500">
                Get a bot token from @BotFather on Telegram for C2 integration
              </p>
            </div>

            <div className="flex space-x-2 pt-4">
              <Button
                onClick={handleCreateUser}
                disabled={createUserMutation.isPending}
                className="bg-green-600 hover:bg-green-700 text-white"
              >
                Create User
              </Button>
              <Button
                onClick={() => setShowAddUser(false)}
                variant="outline"
                className="border-gray-600 text-gray-300"
              >
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Users List */}
      <div className="grid gap-4">
        {users?.map((user: User) => (
          <Card key={user.id} className="bg-gray-900 border-gray-800">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <div className="w-10 h-10 bg-gray-700 rounded-full flex items-center justify-center">
                    <Shield className="w-5 h-5 text-blue-400" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-3">
                      <h3 className="text-white font-medium">{user.username}</h3>
                      <Badge className={`px-2 py-1 text-xs ${getRoleBadgeColor(user.role)}`}>
                        {user.role.toUpperCase()}
                      </Badge>
                      {user.hasTelegramBot && (
                        <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
                          <Bot className="w-3 h-3 mr-1" />
                          Telegram
                        </Badge>
                      )}
                      {user.active ? (
                        <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
                          <UserCheck className="w-3 h-3 mr-1" />
                          Active
                        </Badge>
                      ) : (
                        <Badge className="bg-red-500/20 text-red-400 border-red-500/30">
                          <UserX className="w-3 h-3 mr-1" />
                          Inactive
                        </Badge>
                      )}
                    </div>
                    <p className="text-gray-400 text-sm">
                      Created: {new Date(user.createdAt).toLocaleDateString()}
                      {user.lastLogin && ` • Last login: ${new Date(user.lastLogin).toLocaleDateString()}`}
                    </p>
                  </div>
                </div>
                
                <div className="flex items-center space-x-2">
                  <Button
                    size="sm"
                    variant="outline"
                    className="border-gray-600 text-gray-300"
                    onClick={() => setEditingUser(user)}
                  >
                    <Edit3 className="w-4 h-4" />
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="border-red-600 text-red-400 hover:bg-red-600 hover:text-white"
                    onClick={() => deleteUserMutation.mutate(user.id)}
                  >
                    <Trash2 className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {users?.length === 0 && (
        <Card className="bg-gray-900 border-gray-800">
          <CardContent className="p-12 text-center">
            <Users className="w-12 h-12 text-gray-600 mx-auto mb-4" />
            <h3 className="text-gray-400 text-lg mb-2">No Users Found</h3>
            <p className="text-gray-500 mb-4">Create your first user to start managing access</p>
            <Button
              onClick={() => setShowAddUser(true)}
              className="bg-green-600 hover:bg-green-700 text-white"
            >
              <Plus className="w-4 h-4 mr-2" />
              Add First User
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
