package io.github.cyberstamp.maven.assembly.sbom;

import java.util.List;

import org.cyclonedx.model.OrganizationalEntity;

/**
 * User-configurable metadata for the main BOM component.
 *
 * <p>
 * Fields set here are applied to the CycloneDX metadata component
 * alongside the automatically derived group, name, version, PURL,
 * and licenses. All fields are optional — {@code null} values are
 * ignored.
 * </p>
 */
public class ProductInfo {

    private String cpe;
    private String description;
    private String publisher;
    private String copyright;
    private Organization supplier;
    private Organization manufacturer;

    /** CPE 2.2 or 2.3 identifier for the product. */
    public String getCpe() {
        return cpe;
    }

    public void setCpe(String cpe) {
        this.cpe = cpe;
    }

    /** Free-text description of the product. */
    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    /** Publisher name. */
    public String getPublisher() {
        return publisher;
    }

    public void setPublisher(String publisher) {
        this.publisher = publisher;
    }

    /** Copyright text. */
    public String getCopyright() {
        return copyright;
    }

    public void setCopyright(String copyright) {
        this.copyright = copyright;
    }

    /** The organization that supplied the component. */
    public Organization getSupplier() {
        return supplier;
    }

    public void setSupplier(Organization supplier) {
        this.supplier = supplier;
    }

    /** The organization that manufactured the component. */
    public Organization getManufacturer() {
        return manufacturer;
    }

    public void setManufacturer(Organization manufacturer) {
        this.manufacturer = manufacturer;
    }

    /**
     * An organization identified by name and URL.
     *
     * <p>
     * Designed for XML binding in both Maven plugin {@code @Parameter}
     * and assembly plugin {@code <configuration>} contexts.
     * </p>
     */
    public static class Organization {

        private String name;
        private String url;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        /**
         * Converts to a CycloneDX {@link OrganizationalEntity}.
         *
         * @return the entity, or {@code null} if {@code name} is not set
         *         (CycloneDX requires name on organizational entities)
         */
        OrganizationalEntity toModel() {
            if (name == null) {
                return null;
            }
            OrganizationalEntity entity = new OrganizationalEntity();
            entity.setName(name);
            if (url != null) {
                entity.setUrls(List.of(url));
            }
            return entity;
        }
    }
}
