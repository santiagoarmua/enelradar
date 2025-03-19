package entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name="payment")
    public class Payment {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Integer id;

        @ManyToOne
        @JoinColumn(name = "user_id", nullable = false)
        private User user; // Usuario que paga

        @ManyToOne
        @JoinColumn(name = "passline_id", nullable = false)
        private Passline passline; // Entrada comprada

        @Column(nullable = false)
        private Double amount; // Monto pagado

        @Column(nullable = false)
        private String paymentMethod; // Ejemplo: "CREDIT_CARD", "PAYPAL"

        @Column(nullable = false)
        private LocalDateTime paymentDate; // Fecha de pago

    public Payment(){}

    public Payment(Integer id, User user, Passline passline, Double amount, String paymentMethod, LocalDateTime paymentDate) {
        this.id = id;
        this.user = user;
        this.passline = passline;
        this.amount = amount;
        this.paymentMethod = paymentMethod;
        this.paymentDate = paymentDate;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Passline getPassline() {
        return passline;
    }

    public void setPassline(Passline passline) {
        this.passline = passline;
    }

    public Double getAmount() {
        return amount;
    }

    public void setAmount(Double amount) {
        this.amount = amount;
    }

    public String getPaymentMethod() {
        return paymentMethod;
    }

    public void setPaymentMethod(String paymentMethod) {
        this.paymentMethod = paymentMethod;
    }

    public LocalDateTime getPaymentDate() {
        return paymentDate;
    }

    public void setPaymentDate(LocalDateTime paymentDate) {
        this.paymentDate = paymentDate;
    }

    @Override
    public String toString() {
        return "Payment{" +
                "id=" + id +
                ", user=" + user +
                ", passline=" + passline +
                ", amount=" + amount +
                ", paymentMethod='" + paymentMethod + '\'' +
                ", paymentDate=" + paymentDate +
                '}';
    }
}


