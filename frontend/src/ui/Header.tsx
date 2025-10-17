export const Header = () => {
  return (
    <header
      style={{
        padding: "1.5rem 2rem",
        borderBottom: "1px solid rgba(255, 255, 255, 0.08)",
        display: "flex",
        alignItems: "center",
        gap: "1.5rem"
      }}
    >
      <img src="/logo.png" alt="Hecate Logo" style={{ height: "48px", width: "48px" }} />
      <div>
        <h1 style={{ margin: 0, fontSize: "1.5rem" }}>Hecate Cyber Defense</h1>
        <p style={{ margin: 0, color: "rgba(255,255,255,0.75)" }}>
          KI-gestuetzte Schwachstellenanalyse und proaktive Verteidigung
        </p>
      </div>
    </header>
  );
};
