package entity;

import jakarta.persistence.*;

import java.io.Serializable;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;

@Entity
@Table(name="passline")
public class Passline implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer idPassline;

        @ManyToOne
        @JoinColumn(name = "user_id", nullable = false)
        private User user; // Usuario que compró la entrada

        @ManyToOne
        @JoinColumn(name = "show_id", nullable = false)
        private Show show; // Evento al que pertenece la entrada

        @Column(nullable = false, unique = true, length = 50)
        private String code; // Código único del ticket

        @Column(nullable = false)
        private LocalDate purchaseDate; // Fecha de compra

        @Column(nullable = false)
        private LocalTime purchaseTime;

        @Column(nullable = false)
        private Double price; // Precio de la entrada

        @Column(nullable = false)
        private Boolean isUsed; // Indica si la entrada ya fue utilizada

        @Column(length = 255)
        private String qrCode; // Imagen o URL del código QR de la entrada

    public Passline(){}

    public Passline(Integer idPassline, User user, Show show, String code, LocalDate purchaseDate, LocalTime purchaseTime, Double price, Boolean isUsed, String qrCode) {
        this.idPassline = idPassline;
        this.user = user;
        this.show = show;
        this.code = code;
        this.purchaseDate = purchaseDate;
        this.purchaseTime = purchaseTime;
        this.price = price;
        this.isUsed = isUsed;
        this.qrCode = qrCode;
    }

    public Integer getIdPassline() {
        return idPassline;
    }

    public void setIdPassline(Integer idPassline) {
        this.idPassline = idPassline;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Show getShow() {
        return show;
    }

    public void setShow(Show show) {
        this.show = show;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public LocalDate getPurchaseDate() {
        return purchaseDate;
    }

    public void setPurchaseDate(LocalDate purchaseDate) {
        this.purchaseDate = purchaseDate;
    }

    public LocalTime getPurchaseTime() {
        return purchaseTime;
    }

    public void setPurchaseTime(LocalTime purchaseTime) {
        this.purchaseTime = purchaseTime;
    }

    public Double getPrice() {
        return price;
    }

    public void setPrice(Double price) {
        this.price = price;
    }

    public Boolean getUsed() {
        return isUsed;
    }

    public void setUsed(Boolean used) {
        isUsed = used;
    }

    public String getQrCode() {
        return qrCode;
    }

    public void setQrCode(String qrCode) {
        this.qrCode = qrCode;
    }

    @Override
    public String toString() {
        return "Passline{" +
                "idPassline=" + idPassline +
                ", user=" + user +
                ", show=" + show +
                ", code='" + code + '\'' +
                ", purchaseDate=" + purchaseDate +
                ", purchaseTime=" + purchaseTime +
                ", price=" + price +
                ", isUsed=" + isUsed +
                ", qrCode='" + qrCode + '\'' +
                '}';
    }
}



