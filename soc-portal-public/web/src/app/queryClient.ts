import { QueryClient } from '@tanstack/react-query';
import { ApiError } from '@/lib/api';
import { QUERY_STALE_MS } from '@/lib/constants';

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: QUERY_STALE_MS,
      refetchOnWindowFocus: false,
      retry: (n, e) => !(e instanceof ApiError && e.status < 500) && n < 1,
    },
    mutations: { retry: 0 },
  },
});
