import { useQuery } from "@tanstack/react-query";

export function useAdminAuth() {
  const { data: adminUser, isLoading, error } = useQuery({
    queryKey: ["/api/admin/me"],
    retry: false,
  });

  return {
    adminUser,
    isLoading,
    isAuthenticated: !!adminUser,
    error,
  };
}
