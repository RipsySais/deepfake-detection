import { AuthProvider } from "./contexts/AuthContext";

export default function App() {
  return (
    <AuthProvider>
      {/* Le reste de ton app */}
    </AuthProvider>
  );
}
