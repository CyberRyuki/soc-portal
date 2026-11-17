import { useQuery } from '@tanstack/react-query';
import { api, qs } from '@/lib/api';
import type { IntelOverview, IocLegacySearch } from '@/types/api';

export const useIntelPanel = () =>
  useQuery({
    queryKey: ['intel-panel'],
    queryFn: () =>
      api.get<IntelOverview & { err_eventos?: string; err_iocs?: string; err_shuffle?: string }>('api/intel'),
    staleTime: 120_000,
  });
export const useIocSearch = (q: string) =>
  useQuery({
    queryKey: ['ioc-search', q],
    queryFn: () =>
      api.get<IocLegacySearch & { err_misp?: string; err_wazuh?: string; err_intel?: string }>(
        `api/ioc${qs({ q })}`,
      ),
    enabled: q.trim().length >= 3,
  });
