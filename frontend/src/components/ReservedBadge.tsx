interface ReservedBadgeProps {
  label?: string;
}

export const ReservedBadge = ({ label = "Reserved" }: ReservedBadgeProps) => (
  <span className="tag">{label}</span>
);
