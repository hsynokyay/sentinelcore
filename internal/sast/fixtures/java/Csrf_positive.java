public class CsrfPositive {
    public boolean verifyCsrf(String submitted, String stored) {
        return submitted.equals(stored);
    }
}
