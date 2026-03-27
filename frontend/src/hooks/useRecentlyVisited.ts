import { useCallback, useRef } from "react";
import { usePersistentState } from "./usePersistentState";

type RecentVisit = {
  id: string;
  title: string;
  visitedAt: number;
};

const MAX_RECENT = 10;
const STORAGE_KEY = "recently_visited_vulnerabilities";

export const useRecentlyVisited = () => {
  const [visits, setVisits] = usePersistentState<RecentVisit[]>(STORAGE_KEY, []);
  const visitsRef = useRef(visits);
  visitsRef.current = visits;

  const addVisit = useCallback(
    (id: string, title: string) => {
      const filtered = visitsRef.current.filter((v) => v.id !== id);
      setVisits([{ id, title, visitedAt: Date.now() }, ...filtered].slice(0, MAX_RECENT));
    },
    [setVisits]
  );

  const removeVisit = useCallback(
    (id: string) => {
      setVisits(visitsRef.current.filter((v) => v.id !== id));
    },
    [setVisits]
  );

  return { recentVulnerabilities: visits, addVisit, removeVisit };
};
