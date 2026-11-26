/** How a role reads in the interface. */
export const roleLabel = (role: string, t: (english: string, german: string) => string): string => {
  switch (role) {
    case "admin":
      return t("Admin", "Admin");
    case "editor":
      return t("Editor", "Editor");
    case "viewer":
      return t("Viewer", "Leser");
    default:
      return role;
  }
};
